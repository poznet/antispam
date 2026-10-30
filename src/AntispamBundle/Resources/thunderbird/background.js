/*
 * Antispam Pancernapanda — Thunderbird plugin (background script).
 *
 * Not logged in: marking a message as junk (Thunderbird's own junk button, the
 * toolbar button or the context menu) reports it to antispam, which records
 * its fingerprints in the shared spam DB.
 *
 * Logins are per Thunderbird account (1.3.0+): each account that has its own
 * mailbox in antispam can be logged in with that mailbox's e-mail + plugin /
 * IMAP password. Reports from a logged-in account teach that mailbox's rules
 * (spam → blacklist, not-spam → whitelist), and new mail arriving to it can be
 * sent to antispam for a check; the plugin then marks / moves it.
 *
 * Accounts without their own login ("obce konta") follow the setting
 * foreignMode:
 *   report_only (default) - spam / phishing go to the admin only (shared
 *                fingerprints, phishing copy), authenticated with another
 *                account's login but with "scope": "report_only", so no rules
 *                are learned for that mailbox; "To nie spam" is disabled;
 *   linked     - old behaviour: treated as the default login's mailbox;
 *   off        - nothing is sent, the buttons only file the message locally.
 *
 * "Zgłoś phishing" sends the whole message (attachments included, up to the
 * server's limit) for the admin to inspect, and files it as junk.
 *
 * Server API: docs/thunderbird.md (/api/plugin/*).
 */

"use strict";

const DEFAULTS = {
  server: "",           // base URL of the antispam instance (from config.json when empty)
  autoCheck: true,      // logged-in accounts: check new mail on arrival
  reportOnJunk: true,   // report when the user marks a message as junk / not junk
  spamAction: "move",   // move | mark | none
  quarantineAction: "none", // move | mark | none
  moveOnReport: true,   // move to Junk after reporting from the button / menu
  notify: true,
  foreignMode: "report_only", // report_only | linked | off - accounts without their own login
};
const FOREIGN_MODES = ["report_only", "linked", "off"];

// Key of a login that matches no Thunderbird account (a login from plugin
// 1.2.x whose e-mail is not an identity of any account). Used as the default
// login for accounts without their own.
const GENERAL_LOGIN = "*";

// Only the head of a message is needed for scoring (headers + text body);
// attachments past this point are cut off. Kept so the base64 JSON body stays
// under 1 MiB - the default request limit of an nginx reverse proxy. The
// server can lower it (or raise the phishing limit) with max_upload_bytes in
// /api/plugin/status.
const MAX_UPLOAD_BYTES = 700 * 1024;
// Phishing reports carry the whole message (attachments too) up to the
// server's max_upload_bytes (never more than phishing_max_bytes,
// PhishingReportService::MAX_RAW_BYTES). When a proxy in front of antispam
// still rejects the body (413), the report is resent cut to MAX_UPLOAD_BYTES.
const MAX_PHISHING_BYTES = 10 * 1024 * 1024;
// Server limits from /api/plugin/status are cached this long.
const LIMITS_TTL_MS = 10 * 60 * 1000;
const LIMITS_TIMEOUT_MS = 8 * 1000;
// Requests run one after another (enqueue); a request that never answers would
// stall every later click, so each one is aborted after this long.
const REQUEST_TIMEOUT_MS = 30 * 1000;
const UPLOAD_TIMEOUT_MS = 120 * 1000;
// Reading a message that is not stored offline downloads it from the IMAP
// server; a stalled connection must not hang the action forever.
const GETRAW_TIMEOUT_MS = 60 * 1000;
// Any other Thunderbird API call (junk flag, move, folder lookup,
// notification...) that has not settled after this long is given up on: one
// promise that never settles must not block every later click (1.2.1: "spam
// can be reported only once after a restart").
const STEP_TIMEOUT_MS = 20 * 1000;
// Last-resort watchdog of a whole queued job; the queue moves on after it.
const MANUAL_JOB_TIMEOUT_MS = 3 * 60 * 1000;
const AUTO_JOB_TIMEOUT_MS = 10 * 60 * 1000;
// Thunderbird's own junk classifier flags messages right after they arrive;
// junk changes within this window of arrival are not treated as user verdicts.
const ARRIVAL_GRACE_MS = 2 * 60 * 1000;

// Server URL baked into config.json by the antispam download endpoint
// (instance build). The generic build (addons.thunderbird.net) has no
// config.json: the user enters the address on first run (settings page).
const bundledServer = fetch(messenger.runtime.getURL("config.json"))
  .then(r => r.json())
  .then(c => normalizeServer(c.server))
  .catch(() => "");
const BUTTON_TITLE = "Zgłoś spam (Antyspam)";
const ownChanges = new Set();   // message ids whose junk flag we changed ourselves
const arrivals = new Map();     // message id → arrival timestamp
const movedTo = new Map();      // old message id → { id, t } after a move (onMoved)

// --- event log (shown on the settings page, "Diagnostyka") -----------------

const EVENT_LOG_MAX = 200;
const EVENT_DETAIL_MAX = 2000;
let eventWrite = Promise.resolve();

/** Detail of an event as "key: value" lines; objects are flattened, empty values skipped. */
function detailText(detail) {
  if (detail === undefined || detail === null || detail === "") return "";
  if (typeof detail === "string") return detail.slice(0, EVENT_DETAIL_MAX);
  const lines = [];
  for (const [k, v] of Object.entries(detail)) {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) continue;
    lines.push(k + ": " + (typeof v === "object" ? JSON.stringify(v) : String(v)));
  }
  return lines.join("\n").slice(0, EVENT_DETAIL_MAX);
}

/**
 * Remember what the plugin did (clicks, requests, errors) - readable on the
 * settings page. Never pass tokens, passwords or message bodies here.
 */
function logEvent(kind, ok, text, detail) {
  const entry = { t: Date.now(), kind, ok: !!ok, text: String(text || "").slice(0, 300) };
  const d = detailText(detail);
  if (d) entry.detail = d;
  eventWrite = eventWrite.then(async () => {
    const { eventLog = [] } = await messenger.storage.local.get("eventLog");
    eventLog.unshift(entry);
    await messenger.storage.local.set({ eventLog: eventLog.slice(0, EVENT_LOG_MAX) });
  }).catch(e => console.warn("antispam: event log", e));
  return eventWrite;
}

function errorText(e) {
  return (e && e.message) || String(e);
}

// Steps (Thunderbird API calls) currently waiting, for the "hung on step" log.
const pendingSteps = new Map();
let stepSeq = 0;

/**
 * Await a Thunderbird API call with a time limit. A call that does not settle
 * in `ms` rejects with an error naming the step (and is logged as hung), so
 * the job and the queue behind it go on.
 */
function step(name, promiseOrFn, ms = STEP_TIMEOUT_MS) {
  const id = ++stepSeq;
  pendingSteps.set(id, name);
  let timer;
  const work = Promise.resolve().then(() => (typeof promiseOrFn === "function" ? promiseOrFn() : promiseOrFn));
  const limit = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      const err = new Error(name + ": Thunderbird nie odpowiedział w " + Math.round(ms / 1000) + " s");
      err.hung = name;
      logEvent("error", false, "Zadanie zawieszone na kroku " + name + " (" + Math.round(ms / 1000) + " s) - pomijam ten krok");
      reject(err);
    }, ms);
  });
  return Promise.race([work, limit]).finally(() => {
    clearTimeout(timer);
    pendingSteps.delete(id);
  });
}

// --- settings ----------------------------------------------------------------

async function settings() {
  const s = Object.assign({}, DEFAULTS, await messenger.storage.local.get(Object.keys(DEFAULTS)));
  s.bundledServer = await bundledServer;
  s.server = normalizeServer(s.server) || s.bundledServer;
  if (!FOREIGN_MODES.includes(s.foreignMode)) s.foreignMode = DEFAULTS.foreignMode;
  return s;
}

// First run of a build without a server address (generic build): open the
// settings page, which asks for the address.
messenger.runtime.onInstalled.addListener(async details => {
  if (!details || details.reason !== "install") return;
  try {
    const s = await settings();
    if (!s.server) {
      logEvent("setup", false, "Brak adresu serwera - otwieram ustawienia (pierwsze uruchomienie)");
      await messenger.runtime.openOptionsPage();
    }
  } catch (e) {
    console.warn("antispam: first run", e);
  }
});

// --- Thunderbird accounts and logins ----------------------------------------

/** Mail accounts (with at least one identity): [{id, name, type, emails}]. */
async function listAccounts() {
  let list = [];
  try {
    if (messenger.accounts && messenger.accounts.list) list = (await step("lista kont (accounts.list)", () => messenger.accounts.list(false))) || [];
  } catch (e) {
    console.warn("antispam: accounts.list", e);
  }
  return list.map(a => ({
    id: a.id,
    name: a.name || a.id,
    type: a.type,
    emails: (a.identities || []).map(i => (i.email || "").toLowerCase()).filter(Boolean),
  })).filter(a => a.emails.length);
}

async function accountInfo(accountId) {
  if (!accountId) return { id: null, name: "(nieznane konto)", emails: [] };
  try {
    const acc = await step("dane konta (accounts.get)", () => messenger.accounts.get(accountId));
    if (acc) {
      return {
        id: acc.id || accountId,
        name: acc.name || accountId,
        emails: (acc.identities || []).map(i => (i.email || "").toLowerCase()).filter(Boolean),
      };
    }
  } catch (e) { /* ignore */ }
  return { id: accountId, name: accountId, emails: [] };
}

function folderAccountId(folder) {
  return folder && folder.accountId;
}

// Writes to the "logins" key run one after another (read-modify-write).
let loginWrite = Promise.resolve();
let migration = null;

/**
 * Plugin 1.2.x kept one login (token, email). Move it to the Thunderbird
 * account that has that e-mail as an identity; with no such account it stays
 * as the general login ("*"), the default for accounts without their own.
 */
function migrateLegacyLogin() {
  if (!migration) {
    migration = (async () => {
      const { token = "", email = "", logins } = await messenger.storage.local.get(["token", "email", "logins"]);
      if (!token) return;
      const next = Object.assign({}, logins || {});
      const accounts = await listAccounts();
      const match = accounts.find(a => a.emails.includes(String(email).toLowerCase()));
      const key = match ? match.id : GENERAL_LOGIN;
      if (!next[key]) next[key] = { token, email, expires_at: null };
      await messenger.storage.local.set({ logins: next, token: "", email: "" });
      logEvent("login", true, "Przeniesiono logowanie " + email + (match ? " na konto " + match.name : " jako logowanie ogólne (brak konta Thunderbirda z tym adresem)"));
    })().catch(e => { migration = null; console.warn("antispam: login migration", e); });
  }
  return migration;
}

async function getLogins() {
  await migrateLegacyLogin();
  await loginWrite;
  const { logins } = await messenger.storage.local.get("logins");
  return Object.assign({}, logins || {});
}

function updateLogins(fn) {
  loginWrite = loginWrite.then(async () => {
    await migrateLegacyLogin();
    const { logins } = await messenger.storage.local.get("logins");
    const next = Object.assign({}, logins || {});
    fn(next);
    await messenger.storage.local.set({ logins: next });
  });
  const p = loginWrite;
  loginWrite = loginWrite.catch(e => console.warn("antispam: logins", e));
  return p;
}

/** Login of one Thunderbird account (or "*") is gone: token expired, account removed, logout. */
async function dropLogin(key, reason) {
  const logins = await getLogins();
  if (!logins[key]) return;
  await updateLogins(l => { delete l[key]; });
  logEvent("login", false, "Wylogowano " + (logins[key].email || "") + " (" + reason + ")", { konto: key });
}

/**
 * The login used for accounts without their own: the general one ("*"),
 * else the first logged-in account in Thunderbird's account order.
 */
async function defaultLogin(logins, accounts) {
  if (logins[GENERAL_LOGIN]) return Object.assign({ key: GENERAL_LOGIN }, logins[GENERAL_LOGIN]);
  for (const a of accounts || await listAccounts()) {
    if (logins[a.id]) return Object.assign({ key: a.id }, logins[a.id]);
  }
  const keys = Object.keys(logins);
  return keys.length ? Object.assign({ key: keys[0] }, logins[keys[0]]) : null;
}

/**
 * How messages of a Thunderbird account are handled:
 *   kind own         - the account has its own login (rules, ham, checks);
 *        report_only - foreign account, report to the admin only (login may be null = anonymous);
 *        linked      - foreign account treated as the default login's mailbox;
 *        off         - foreign account, the plugin sends nothing;
 *        anonymous   - foreign account, linked mode, but no login at all.
 */
async function contextFor(accountId) {
  const s = await settings();
  const logins = await getLogins();
  const account = await accountInfo(accountId);
  const ctx = { account, kind: "anonymous", login: null, mode: s.foreignMode };
  if (accountId && logins[accountId]) {
    ctx.kind = "own";
    ctx.login = Object.assign({ key: accountId }, logins[accountId]);
    return ctx;
  }
  if (s.foreignMode === "off") {
    ctx.kind = "off";
    return ctx;
  }
  ctx.login = await defaultLogin(logins);
  ctx.kind = s.foreignMode === "linked" ? (ctx.login ? "linked" : "anonymous") : "report_only";
  return ctx;
}

/** Short description of where a report goes, for notifications, menu titles and the log. */
function targetText(ctx) {
  switch (ctx.kind) {
    case "own": return "skrzynka " + ctx.login.email;
    case "linked": return "skrzynka " + ctx.login.email + " (konto " + accountLabel(ctx.account) + " bez własnego logowania)";
    case "report_only": return "tylko do administratora" + (ctx.login ? "" : ", anonimowo");
    case "off": return "antyspam wyłączony dla tego konta";
    default: return "anonimowo";
  }
}

function accountLabel(account) {
  return account.emails[0] || account.name || "?";
}

/** What a log entry says about the account / login of an action (never the token). */
function contextDetail(ctx) {
  return {
    konto: ctx.account.name + (ctx.account.emails.length ? " <" + ctx.account.emails.join(", ") + ">" : ""),
    tryb: ctx.kind,
    logowanie: ctx.login ? ctx.login.email : "brak (anonimowo)",
  };
}

// --- API ---------------------------------------------------------------------

/** Response fields worth keeping in the event log (no message content, no tokens). */
function responseSummary(data) {
  const out = {};
  for (const k of ["error", "message", "verdict", "sender", "signals", "rules", "retroactive", "phishing_id", "duplicate",
    "scope", "mailbox", "authenticated", "email", "decision", "score", "spam_threshold", "version", "server_version", "report_only",
    "created", "active", "job", "last"]) {
    if (data && data[k] !== undefined && data[k] !== null && data[k] !== "") out[k] = data[k];
  }
  return out;
}

/**
 * Request to antispam. `login` ({key, token, email} or null) authenticates
 * it; a 401 drops only that login.
 */
async function api(path, { method = "GET", body = null, login = null, timeout = REQUEST_TIMEOUT_MS, quietOk = false } = {}) {
  const s = await settings();
  if (!s.server) throw new Error("Nie ustawiono adresu serwera antyspamu (Ustawienia wtyczki).");
  const headers = { "Accept": "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (login && login.token) headers["Authorization"] = "Bearer " + login.token;
  const who = login && login.email ? login.email : "bez logowania";

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  const t0 = Date.now();
  let res;
  try {
    res = await fetch(s.server + path, {
      method,
      headers,
      body: body === null ? null : JSON.stringify(body),
      credentials: "omit",
      signal: ctrl.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") {
      const err = new Error("serwer nie odpowiedział w " + Math.round(timeout / 1000) + " s");
      err.timeout = true;
      logEvent("api", false, method + " " + path + ": " + err.message, { logowanie: who, czas: (Date.now() - t0) + " ms" });
      throw err;
    }
    logEvent("api", false, method + " " + path + ": " + e.message + " (brak połączenia, uprawnienia lub certyfikat)", { logowanie: who, czas: (Date.now() - t0) + " ms", serwer: s.server });
    throw new Error(e.message);
  } finally {
    clearTimeout(timer);
  }
  const ms = Date.now() - t0;
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (res.status === 401 && login && login.token && login.key) {
    // Token expired or account removed — only this account's login is dropped.
    await dropLogin(login.key, "serwer odrzucił logowanie (HTTP 401)");
  }
  if (!res.ok) {
    const err = new Error(data.message || data.error
      || (res.status === 413 ? "wiadomość za duża dla serwera (HTTP 413)" : "HTTP " + res.status));
    err.status = res.status;
    logEvent("api", false, method + " " + path + ": HTTP " + res.status + " (" + ms + " ms)" + (data.error ? " " + data.error : ""),
      Object.assign({ logowanie: who }, responseSummary(data)));
    throw err;
  }
  if (!quietOk) logEvent("api", true, method + " " + path + ": HTTP " + res.status + " (" + ms + " ms)", Object.assign({ logowanie: who }, responseSummary(data)));
  return data;
}

/**
 * Server facts from /api/plugin/status (upload limits, report_only support).
 * Cached; on any error the built-in defaults are used (and report_only is
 * treated as unsupported).
 */
let limitsCache = null;
async function serverLimits() {
  const s = await settings();
  if (limitsCache && limitsCache.server === s.server && Date.now() - limitsCache.t < limitsCache.ttl) {
    return limitsCache.limits;
  }
  const limits = { maxUpload: MAX_UPLOAD_BYTES, phishingMax: MAX_PHISHING_BYTES, known: false, reportOnly: false };
  let ttl = LIMITS_TTL_MS;
  try {
    const st = await api("/api/plugin/status", { timeout: LIMITS_TIMEOUT_MS, quietOk: true });
    const max = Number(st.max_upload_bytes);
    if (Number.isFinite(max) && max >= 16 * 1024) {
      limits.maxUpload = max;
      limits.known = true;
    }
    const pmax = Number(st.phishing_max_bytes);
    if (Number.isFinite(pmax) && pmax > 0) limits.phishingMax = pmax;
    limits.reportOnly = st.report_only === true;
  } catch (e) {
    // Unreachable server: use the defaults and do not ask again before every message.
    console.warn("antispam: could not read server limits", e);
    ttl = 60 * 1000;
  }
  limitsCache = { server: s.server, t: Date.now(), ttl, limits };
  return limits;
}

/** Size cap for spam reports and checks: the head is enough, the server may ask for less. */
async function reportLimit() {
  return Math.min(MAX_UPLOAD_BYTES, (await serverLimits()).maxUpload);
}

/**
 * Login and request fields of a report (spam / phishing) for `ctx`:
 * {login, extra, note} or {refused: text}. Foreign accounts in report_only
 * mode send "scope": "report_only" with their address; a server without
 * report_only support (older antispam) would learn rules for the login's
 * mailbox, so the report goes without a token there (spam) or not at all
 * (phishing, needs a login).
 */
async function reportAuth(ctx, { phishing = false } = {}) {
  const from = ctx.account.emails.slice(0, 5);
  if (ctx.kind === "own") return { login: ctx.login, extra: {}, note: "" };
  if (ctx.kind === "linked") return { login: ctx.login, extra: from.length ? { reported_from: from } : {}, note: "" };
  if (ctx.kind === "report_only") {
    if (!ctx.login) {
      return phishing
        ? { refused: "Zgłoszenie phishingu wymaga zalogowania we wtyczce (dowolnego konta) - wiadomość trafia w całości do administratora." }
        : { login: null, extra: { scope: "report_only" }, note: "anonimowo" };
    }
    if (!(await serverLimits()).reportOnly) {
      return phishing
        ? { refused: "Serwer antyspamu nie obsługuje zgłoszeń z kont bez logowania (zaktualizuj antyspam) - zaloguj to konto we wtyczce albo zmień ustawienie „Wiadomości z kont bez logowania”." }
        : { login: null, extra: { scope: "report_only" }, note: "anonimowo - serwer nie obsługuje trybu „tylko do administratora”" };
    }
    return { login: ctx.login, extra: Object.assign({ scope: "report_only" }, from.length ? { reported_from: from } : {}), note: "" };
  }
  return { login: null, extra: {}, note: "anonimowo" };
}

/** System notification. Not awaited by the caller's job: a notification that never shows must not block it. */
async function notify(title, message) {
  const s = await settings();
  if (!s.notify) return;
  step("powiadomienie (notifications.create)", () => messenger.notifications.create({
    type: "basic",
    iconUrl: messenger.runtime.getURL("icons/icon-64.png"),
    title,
    message,
  })).catch(e => console.warn("antispam: notification failed", e));
}

/**
 * Result of an explicit action (button / menu) on the toolbar button, so the
 * user sees something even when system notifications are off. Also logged.
 */
let badgeTimer = null;
async function feedback(ok, text, detail) {
  logEvent("result", ok, text, detail);
  const btn = messenger.messageDisplayAction;
  // Not awaited: the badge is cosmetic and must never hold up the queue.
  Promise.resolve().then(async () => {
    await btn.setBadgeText({ text: ok ? "✓" : "!" });
    await btn.setBadgeBackgroundColor({ color: ok ? "#2e7d32" : "#c62828" });
    await btn.setTitle({ title: "Antyspam: " + text });
  }).catch(() => { /* older Thunderbird */ });
  clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => {
    btn.setBadgeText({ text: "" }).catch(() => {});
    btn.setTitle({ title: BUTTON_TITLE }).catch(() => {});
  }, 30000);
}

/** Explicit action that cannot run as configured: tell the user and open the settings. */
async function needsSetup(text, detail) {
  await notify("Antyspam", text);
  await feedback(false, text, detail);
  step("otwarcie ustawień (openOptionsPage)", () => messenger.runtime.openOptionsPage()).catch(() => { /* ignore */ });
}

// --- message helpers --------------------------------------------------------

/** Subject, sender, folder, size and account of a message for the event log (no content). */
function messageDetail(message, ctx) {
  const d = {
    temat: message.subject || "(bez tematu)",
    nadawca: message.author || "",
    folder: message.folder ? (message.folder.path || message.folder.name || "") : "",
    rozmiar: typeof message.size === "number" ? Math.round(message.size / 1024) + " KiB" : "",
  };
  return ctx ? Object.assign(d, contextDetail(ctx)) : d;
}

/** messages.getRaw() with a time limit (a message not stored offline is downloaded first). */
function getRaw(messageId) {
  return step("odczyt wiadomości (messages.getRaw)", () => messenger.messages.getRaw(messageId), GETRAW_TIMEOUT_MS);
}

/**
 * Message source as returned by messages.getRaw() (binary string or, in newer
 * Thunderbird, a File) cut at `limit` bytes and base64-encoded; `truncated`
 * tells whether it was cut. Works on data read earlier, so the message may
 * have been moved in the meantime.
 */
async function encodeRaw(raw, limit = MAX_UPLOAD_BYTES) {
  let bin;
  let size;
  if (typeof raw === "string") {
    size = raw.length;
    bin = raw.length > limit ? raw.slice(0, limit) : raw;
  } else {
    size = raw.size;
    const buf = new Uint8Array(await raw.slice(0, limit).arrayBuffer());
    bin = "";
    for (let i = 0; i < buf.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    }
  }
  return { base64: btoa(bin), truncated: size > limit, size };
}

/** Raw source of a message as base64, cut at `limit` bytes. */
async function rawSource(messageId, limit = MAX_UPLOAD_BYTES) {
  return encodeRaw(await getRaw(messageId), limit);
}

/**
 * Raw source of a message Thunderbird may have moved since `rawPromise` was
 * started (its junk button files the message into Junk, and the WebExtension
 * id is bound to the folder): the preread data, else the message under its
 * new id.
 */
async function rawAfterMove(message, rawPromise) {
  try {
    return await rawPromise;
  } catch (e) {
    const moved = movedTo.get(message.id);
    if (!moved) throw e;
    return getRaw(moved.id);
  }
}

// Junk folder names used when no folder carries the junk flag (IMAP servers
// that do not advertise \Junk, or a folder Thunderbird has not adopted yet).
const JUNK_NAME_RE = /^(junk|junk e-?mail|spam|bulk mail|śmieci|wiadomości[- ]śmieci|niechciane|spam[- ]?box)$/i;

/** Every folder of an account, flattened (empty list when it cannot be read). */
async function accountFolders(accountId) {
  try {
    const acc = await step("foldery konta (accounts.get)", () => messenger.accounts.get(accountId, true));
    if (acc && acc.folders && acc.folders.length) {
      const out = [];
      const stack = [...acc.folders];
      while (stack.length) {
        const f = stack.shift();
        out.push(f);
        stack.push(...(f.subFolders || []));
      }
      return out;
    }
    if (acc && acc.rootFolder && messenger.folders && messenger.folders.getSubFolders) {
      const out = [];
      const stack = [...(await step("foldery konta (folders.getSubFolders)", () => messenger.folders.getSubFolders(acc.rootFolder.id || acc.rootFolder, true)) || [])];
      while (stack.length) {
        const f = stack.shift();
        out.push(f);
        stack.push(...(f.subFolders || []));
      }
      return out;
    }
  } catch (e) {
    logEvent("local", false, "Nie udało się odczytać folderów konta: " + errorText(e));
  }
  return [];
}

/** Last path segment ("INBOX.Spam", "/INBOX/Spam" -> "Spam"). */
function folderBaseName(f) {
  const name = (f.name || "").trim();
  if (name) return name;
  return String(f.path || "").split(/[\/.]/).filter(Boolean).pop() || "";
}

async function findJunkFolder(accountId) {
  try {
    if (messenger.folders && messenger.folders.query) {
      const found = await step("szukanie folderu Śmieci (folders.query)", () => messenger.folders.query({ accountId, specialUse: ["junk"] }));
      if (found && found.length) return found[0];
    }
  } catch (e) { /* older Thunderbird */ }

  const folders = await accountFolders(accountId);
  const flagged = folders.find(f => (f.specialUse || []).includes("junk") || f.type === "junk");
  if (flagged) return flagged;

  // No junk flag anywhere: take a folder named like one (Spam, Junk, Śmieci...).
  const named = folders.find(f => JUNK_NAME_RE.test(folderBaseName(f)));
  if (named) {
    logEvent("local", true, "Folder Śmieci nie jest oznaczony na koncie - używam folderu " + (named.path || named.name) + " (dopasowanie po nazwie)");
    return named;
  }
  logEvent("local", false, "Nie znaleziono folderu Śmieci/Spam/Junk na koncie", {
    foldery: folders.map(f => f.path || f.name).slice(0, 40).join(", ") || "(brak listy)",
    rada: "W Thunderbirdzie: Ustawienia konta > Ustawienia niechcianej poczty > \"Przenoś nowe wiadomości niechciane do\" - wskaż folder, albo załóż folder Spam na serwerze",
  });
  return null;
}

async function setJunk(message, junk) {
  ownChanges.add(message.id);
  try {
    await step(junk ? "oznaczenie jako śmieci (messages.update)" : "zdjęcie oznaczenia śmieci (messages.update)", () => messenger.messages.update(message.id, { junk }));
    return true;
  } catch (e) {
    console.warn("antispam: could not set junk flag", e);
    logEvent("local", false, "Nie udało się " + (junk ? "oznaczyć jako śmieci" : "zdjąć oznaczenia śmieci") + ": " + errorText(e), { temat: message.subject || "" });
    return false;
  } finally {
    setTimeout(() => ownChanges.delete(message.id), 10000);
  }
}

async function moveToJunk(message) {
  const junk = await findJunkFolder(folderAccountId(message.folder));
  if (!junk) {
    logEvent("local", false, "Brak folderu Śmieci na koncie - wiadomość została oznaczona jako śmieci, ale nie przeniesiona", { temat: message.subject || "" });
    return false;
  }
  if (message.folder && junk.path === message.folder.path) return true;
  try {
    // Thunderbird 121+ takes the folder id (the MailFolder object is deprecated
    // and gone in MV3); 115 has no folder ids and needs the object.
    await step("przeniesienie do " + (junk.path || "Śmieci") + " (messages.move)", () => messenger.messages.move([message.id], junk.id || junk));
    logEvent("local", true, "Przeniesiono do " + (junk.path || junk.name || "Śmieci"), { temat: message.subject || "" });
    return true;
  } catch (e) {
    console.warn("antispam: move to junk failed", e);
    logEvent("local", false, "Przeniesienie do " + (junk.path || "Śmieci") + " nie powiodło się: " + errorText(e), { temat: message.subject || "" });
    return false;
  }
}

// --- actions ----------------------------------------------------------------

/**
 * Send a user verdict ("spam" | "ham") to antispam. `rawData` is the
 * (pending) result of messages.getRaw() started before the message could be
 * moved; without it the message is read now.
 */
async function report(message, verdict, { quiet = false, manual = false, rawData = null } = {}) {
  const s = await settings();
  const ctx = await contextFor(folderAccountId(message.folder));
  const detail = Object.assign({ akcja: verdict === "spam" ? "zgłoszenie spamu" : "to nie spam" }, messageDetail(message, ctx));
  const fail = async (text, title = "Antyspam — błąd") => {
    if (!quiet) await notify(title, text);
    if (manual) await feedback(false, text, detail);
    else logEvent("result", false, text, detail);
    return null;
  };

  if (ctx.kind === "off") {
    return fail("Antyspam jest wyłączony dla konta " + accountLabel(ctx.account) + " (ustawienie „Wiadomości z kont bez logowania”) - nic nie wysłano.", "Antyspam");
  }
  if (verdict === "ham" && ctx.kind !== "own" && ctx.kind !== "linked") {
    const text = ctx.kind === "report_only"
      ? "„To nie spam” działa tylko dla kont zalogowanych we wtyczce - zaloguj konto " + accountLabel(ctx.account) + " (Ustawienia wtyczki)."
      : "Zgłoszenie „to nie spam” wymaga zalogowania we wtyczce.";
    if (manual) {
      await needsSetup(text, detail);
      return null;
    }
    return fail(text, "Antyspam");
  }
  if (!s.server) {
    const text = "Nie ustawiono adresu serwera antyspamu.";
    if (manual) {
      await needsSetup(text, detail);
      return null;
    }
    return fail(text);
  }
  const auth = verdict === "spam" ? await reportAuth(ctx) : { login: ctx.login, extra: ctx.kind === "linked" && ctx.account.emails.length ? { reported_from: ctx.account.emails.slice(0, 5) } : {}, note: "" };
  if (auth.refused) return fail(auth.refused);
  let raw;
  try {
    const limit = await reportLimit();
    const src = rawData
      ? await encodeRaw(await rawAfterMove(message, rawData), limit)
      : await rawSource(message.id, limit);
    raw = src.base64;
    detail["wysłano"] = Math.round(Math.min(src.size, limit) / 1024) + " KiB" + (src.truncated ? " (obcięte)" : "");
  } catch (e) {
    console.warn("antispam: could not read message", e);
    return fail("Nie udało się odczytać wiadomości do zgłoszenia: " + errorText(e));
  }
  const target = auth.login ? targetText(ctx) : (ctx.kind === "report_only" ? "tylko do administratora, " : "") + "anonimowo";
  detail.cel = target + (auth.note && auth.note !== "anonimowo" ? " (" + auth.note + ")" : "");
  try {
    const res = await api("/api/plugin/report", {
      method: "POST",
      body: Object.assign({ verdict, raw_base64: raw }, auth.extra),
      login: auth.login,
    });
    const who = message.author || res.sender || "";
    const learned = res.rules && res.rules.length;
    const text = (verdict === "spam"
      ? "Zgłoszono spam: " + who + (learned ? " (nadawca zablokowany)" : "")
      : "Oznaczono jako nie-spam: " + who + (learned ? " (nadawca na białej liście)" : "")) + " → " + detail.cel;
    Object.assign(detail, { reguly: res.rules, sygnaly: res.signals, retroaktywnie: res.retroactive });
    if (!quiet) await notify("Antyspam", text);
    if (manual) await feedback(true, text, detail);
    else logEvent("result", true, text, detail);
    return res;
  } catch (e) {
    console.warn("antispam: report failed", e);
    if (e.timeout) {
      // The server stores the report before it answers; a timeout almost
      // always means it is still busy, not that the report was lost.
      const text = "Serwer " + s.server + " nie odpowiedział na czas – zgłoszenie prawdopodobnie zostało przyjęte.";
      if (!quiet) await notify("Antyspam", text);
      if (manual) await feedback(true, text, detail);
      else logEvent("result", true, text, detail);
      return null;
    }
    return fail("Nie udało się wysłać zgłoszenia do " + s.server + ": " + errorText(e) + (e.status ? " (HTTP " + e.status + ")" : ""));
  }
}

/** Mark as junk (and move, if set) right away - the user's click must not wait for the server. */
async function fileAsJunk(message) {
  const s = await settings();
  await setJunk(message, true);
  if (s.moveOnReport) await moveToJunk(message);
}

/** Report as spam from the button / menu and handle the message locally. */
async function reportSpamAndFile(message) {
  // Read the source first: a moved message cannot be read under its old id.
  let raw = null;
  try {
    raw = await getRaw(message.id);
  } catch (e) {
    console.warn("antispam: could not read message", e);
    await feedback(false, "Nie udało się odczytać wiadomości do zgłoszenia: " + errorText(e), messageDetail(message));
  }
  // The report does not wait for the local move (an IMAP move can take long
  // or never confirm); both run side by side.
  const filing = fileAsJunk(message).catch(e => logEvent("local", false, "Lokalne oznaczenie nie powiodło się: " + errorText(e)));
  const sending = raw !== null ? report(message, "spam", { manual: true, rawData: Promise.resolve(raw) }) : Promise.resolve(null);
  await Promise.allSettled([filing, sending]);
}

/**
 * Report a phishing attempt (needs a login: the account's own, or - for an
 * account without one in report_only mode - any other, used only to
 * authenticate). The server keeps the whole message for the admin and treats
 * it as a spam report; locally it is filed as junk like "Zgłoś spam".
 */
async function reportPhishing(message) {
  const s = await settings();
  const ctx = await contextFor(folderAccountId(message.folder));
  const detail = Object.assign({ akcja: "zgłoszenie phishingu" }, messageDetail(message, ctx));
  if (ctx.kind === "off") {
    await fileAsJunk(message).catch(e => logEvent("local", false, "Lokalne oznaczenie nie powiodło się: " + errorText(e)));
    const text = "Antyspam jest wyłączony dla konta " + accountLabel(ctx.account) + " - wiadomość oznaczono lokalnie jako śmieci, nic nie wysłano.";
    await notify("Antyspam", text);
    await feedback(false, text, detail);
    return;
  }
  if (!ctx.login) {
    await needsSetup("Zgłoszenie phishingu wymaga zalogowania we wtyczce (wiadomość trafia w całości do administratora).", detail);
    return;
  }
  const auth = await reportAuth(ctx, { phishing: true });
  if (auth.refused) {
    await needsSetup(auth.refused, detail);
    return;
  }
  // Read now: the move below changes the message id.
  let raw;
  try {
    raw = await getRaw(message.id);
  } catch (e) {
    await feedback(false, "Nie udało się odczytać wiadomości: " + errorText(e), detail);
    return;
  }
  // Filed locally side by side with the upload - the report never waits for the move.
  const filing = fileAsJunk(message).catch(e => logEvent("local", false, "Lokalne oznaczenie nie powiodło się: " + errorText(e)));
  try {
    await uploadPhishing(message, raw, ctx, auth, detail, s);
  } finally {
    await filing;
  }
}

async function uploadPhishing(message, raw, ctx, auth, detail, s) {
  detail.cel = targetText(ctx);
  const send = (body) => api("/api/plugin/phishing", { method: "POST", body: Object.assign(body, auth.extra), login: auth.login, timeout: UPLOAD_TIMEOUT_MS });
  try {
    // As much of the message as the server (and the proxy in front of it) accepts.
    const limits = await serverLimits();
    const limit = Math.min(limits.phishingMax, limits.known ? limits.maxUpload : MAX_PHISHING_BYTES);
    const src = await encodeRaw(raw, limit);
    detail["wysłano"] = Math.round(Math.min(src.size, limit) / 1024) + " KiB" + (src.truncated ? " (obcięte)" : "");
    let res;
    try {
      res = await send({ raw_base64: src.base64, truncated: src.truncated, client: "thunderbird" });
    } catch (e) {
      const fallback = Math.min(MAX_UPLOAD_BYTES, limit);
      // Nothing to gain when what was sent is no bigger than the fallback.
      if (e.status !== 413 || src.base64.length <= Math.ceil(fallback / 3) * 4) throw e;
      // A proxy in front of antispam still limits the body size: send the head of the message.
      logEvent("api", false, "Serwer odrzucił rozmiar (413) - ponawiam z początkiem wiadomości (" + Math.round(fallback / 1024) + " KiB)");
      detail["wysłano"] = Math.round(fallback / 1024) + " KiB (obcięte po HTTP 413)";
      res = await send({ raw_base64: (await encodeRaw(raw, fallback)).base64, truncated: true, client: "thunderbird" });
    }
    const text = "Zgłoszono próbę wyłudzenia: " + (message.author || res.sender || "")
      + (res.duplicate ? " (już była zgłoszona)" : "") + (res.rules && res.rules.length ? " – nadawca zablokowany" : "")
      + " → " + detail.cel;
    Object.assign(detail, { phishing_id: res.phishing_id, duplikat: res.duplicate ? "tak" : "", reguly: res.rules, retroaktywnie: res.retroactive });
    await notify("Antyspam", text);
    await feedback(true, text, detail);
  } catch (e) {
    console.warn("antispam: phishing report failed", e);
    if (e.timeout) {
      // Unlike a spam report the upload itself may have stalled, so only "may have".
      const text = "Serwer " + s.server + " nie odpowiedział na czas – zgłoszenie phishingu mogło zostać przyjęte; sprawdź u administratora, zanim zgłosisz je ponownie.";
      await notify("Antyspam", text);
      await feedback(false, text, detail);
      return;
    }
    const text = "Nie udało się zgłosić phishingu do " + s.server + ": " + errorText(e) + (e.status ? " (HTTP " + e.status + ")" : "");
    await notify("Antyspam — błąd", text);
    await feedback(false, text, detail);
  }
}

async function reportHam(message) {
  const ctx = await contextFor(folderAccountId(message.folder));
  if (ctx.kind === "off") {
    // Nothing is sent for this account; the user still wants it out of junk.
    await setJunk(message, false);
    await feedback(false, "Antyspam jest wyłączony dla konta " + accountLabel(ctx.account) + " - zdjęto tylko lokalne oznaczenie śmieci.", messageDetail(message, ctx));
    return;
  }
  const res = await report(message, "ham", { manual: true });
  if (res) await setJunk(message, false);
}

/** Ask antispam to score a message (accounts with a login) and act on the decision. */
async function check(message, { manual = false, ctx = null } = {}) {
  const s = await settings();
  ctx = ctx || await contextFor(folderAccountId(message.folder));
  const detail = Object.assign({ akcja: "sprawdzenie" }, messageDetail(message, ctx));
  if (ctx.kind !== "own" && ctx.kind !== "linked") {
    if (manual) {
      await needsSetup(ctx.kind === "off"
        ? "Antyspam jest wyłączony dla konta " + accountLabel(ctx.account) + "."
        : "Sprawdzanie wiadomości wymaga zalogowania konta " + accountLabel(ctx.account) + " we wtyczce (adres skrzynki + hasło wtyczki lub IMAP).", detail);
    }
    return null;
  }
  let res;
  try {
    res = await api("/api/plugin/check", { method: "POST", body: { raw_base64: (await rawSource(message.id, await reportLimit())).base64 }, login: ctx.login, quietOk: !manual });
  } catch (e) {
    console.warn("antispam: check failed", e);
    const text = "Sprawdzenie nie powiodło się (" + s.server + "): " + errorText(e);
    if (manual) {
      await notify("Antyspam — błąd", text);
      await feedback(false, text, detail);
    } else {
      logEvent("check", false, text, detail);
    }
    return null;
  }

  const action = res.decision === "spam" ? s.spamAction
    : res.decision === "quarantine" ? s.quarantineAction : "none";
  if (action === "mark" || action === "move") await setJunk(message, true);
  if (action === "move") await moveToJunk(message);

  const labels = { spam: "SPAM", quarantine: "podejrzana", ham: "czysta", whitelisted: "biała lista" };
  const label = labels[res.decision] || res.decision;
  const text = (message.subject || "(bez tematu)") + " — wynik " + res.score + "/" + res.spam_threshold + " (" + targetText(ctx) + ")";
  Object.assign(detail, { decyzja: res.decision, wynik: res.score + "/" + res.spam_threshold, akcja_lokalna: action });
  if (manual || res.decision === "spam") await notify("Antyspam: " + label, text);
  if (manual) await feedback(true, label + ": " + text, detail);
  else if (res.decision !== "ham") logEvent("check", true, "Sprawdzono nową wiadomość: " + label + ": " + text, detail);
  return res;
}

// --- new mail ---------------------------------------------------------------

// Automatic work (on-arrival checks, Thunderbird's junk button) runs one at a
// time; the user's own clicks have a queue of their own so they never wait
// behind a batch of new-mail checks.
let queue = Promise.resolve();
let manualQueue = Promise.resolve();

/**
 * Run `fn` as one job of a queue: exceptions are logged, and a job still
 * running after `ms` is no longer waited for (logged with the steps it is
 * stuck on), so the queue always moves on.
 */
function guardedJob(fn, label, ms) {
  let timer;
  const limit = new Promise(resolve => {
    timer = setTimeout(() => {
      const stuck = [...new Set(pendingSteps.values())];
      logEvent("error", false, label + ": zadanie zawieszone" + (stuck.length ? " na kroku " + stuck.join(", ") : "")
        + " - przerwano oczekiwanie po " + Math.round(ms / 1000) + " s, następne działania wykonują się dalej");
      resolve();
    }, ms);
  });
  const job = Promise.resolve().then(fn).catch(e => {
    console.warn("antispam:", e);
    logEvent("error", false, label + ": " + (e && e.hung ? "zadanie zawieszone na kroku " + e.hung : "nieoczekiwany błąd: " + errorText(e)),
      e && e.stack ? String(e.stack).slice(0, 600) : "");
  });
  return Promise.race([job, limit]).finally(() => clearTimeout(timer));
}

function enqueue(fn, label = "zadanie w tle") {
  queue = queue.then(() => guardedJob(fn, label, AUTO_JOB_TIMEOUT_MS));
  return queue;
}

/**
 * The user's clicks: one after another, each with a watchdog
 * (MANUAL_JOB_TIMEOUT_MS) - every Thunderbird call inside has its own time
 * limit (step), so a click never waits behind a hung earlier one for long.
 */
function enqueueManual(fn, label = "akcja") {
  manualQueue = manualQueue.then(() => guardedJob(fn, label, MANUAL_JOB_TIMEOUT_MS));
  return manualQueue;
}

async function* listMessages(list) {
  let page = list;
  while (page) {
    for (const m of page.messages || []) yield m;
    page = page.id ? await step("następna strona listy (messages.continueList)", () => messenger.messages.continueList(page.id)) : null;
  }
}

messenger.messages.onNewMailReceived.addListener((folder, messageList) => {
  // Note the arrival now, not when the queued job runs: behind a batch of
  // checks that can be minutes later, after the classifier already ran.
  const now = Date.now();
  for (const m of (messageList && messageList.messages) || []) arrivals.set(m.id, now);
  for (const [id, t] of arrivals) if (now - t > ARRIVAL_GRACE_MS) arrivals.delete(id);

  enqueue(async () => {
    const s = await settings();
    // Only accounts logged in with their own mailbox are checked on arrival.
    const ctx = s.autoCheck ? await contextFor(folderAccountId(folder)) : null;
    const checkThis = ctx && ctx.kind === "own";

    for await (const message of listMessages(messageList)) {
      if (!arrivals.has(message.id)) arrivals.set(message.id, now); // later pages
      if (checkThis) await check(message, { ctx });
    }
  }, "sprawdzanie nowej poczty");
});

// Old id → new id of moved messages, so a report can still read a message
// Thunderbird filed away before the queued job got to it.
if (messenger.messages.onMoved) {
  messenger.messages.onMoved.addListener((original, moved) => {
    const now = Date.now();
    const from = (original && original.messages) || [];
    const to = (moved && moved.messages) || [];
    for (let i = 0; i < from.length && i < to.length; i++) movedTo.set(from[i].id, { id: to[i].id, t: now });
    for (const [id, m] of movedTo) if (now - m.t > 60 * 1000) movedTo.delete(id);
  });
}

// Thunderbird's own junk / not-junk buttons.
if (messenger.messages.onUpdated) {
  messenger.messages.onUpdated.addListener((message, changed) => {
    if (!changed || typeof changed.junk !== "boolean") return;
    if (ownChanges.has(message.id)) return;
    const arrived = arrivals.get(message.id);
    // A fresh, unread message: Thunderbird's own classifier, not the user. A
    // message the user has already opened is their verdict even right after arrival.
    if (arrived && Date.now() - arrived < ARRIVAL_GRACE_MS && !message.read) return;
    // Start reading right away: Thunderbird usually moves a junk message to
    // the Junk folder next, and the id stops working once it is moved.
    const rawData = getRaw(message.id);
    rawData.catch(() => {}); // handled in report(); avoids an unhandled rejection meanwhile
    logEvent("junk", true, (changed.junk ? "Oznaczono jako śmieci" : "Oznaczono jako nie-śmieci") + " w Thunderbirdzie: " + (message.subject || "(bez tematu)"), messageDetail(message));
    enqueue(async () => {
      const s = await settings();
      if (!s.reportOnJunk) {
        logEvent("junk", false, "Zgłaszanie przy oznaczaniu śmieci jest wyłączone w ustawieniach");
        return;
      }
      const ctx = await contextFor(folderAccountId(message.folder));
      if (ctx.kind === "off") {
        logEvent("junk", false, "Konto " + accountLabel(ctx.account) + " bez logowania - antyspam wyłączony dla takich kont, nic nie wysłano");
        return;
      }
      if (changed.junk) await report(message, "spam", { rawData });
      else if (ctx.kind === "own" || ctx.kind === "linked") await report(message, "ham", { rawData });
      else logEvent("junk", false, "Nie-śmieci na koncie " + accountLabel(ctx.account) + " bez logowania - nie zgłoszono (wymaga zalogowania tego konta)");
    }, "zgłoszenie z przycisku śmieci Thunderbirda");
  });
}

// --- UI: toolbar button + context menu --------------------------------------

async function displayedMessages(tab) {
  if (!tab || !messenger.messageDisplay) return [];
  if (messenger.messageDisplay.getDisplayedMessages) {
    const r = await step("wyświetlane wiadomości (messageDisplay)", () => messenger.messageDisplay.getDisplayedMessages(tab.id));
    return Array.isArray(r) ? r : (r && r.messages) || [];
  }
  const m = await step("wyświetlana wiadomość (messageDisplay)", () => messenger.messageDisplay.getDisplayedMessage(tab.id));
  return m ? [m] : [];
}

messenger.messageDisplayAction.onClicked.addListener(tab => {
  logEvent("click", true, "Przycisk „Zgłoś spam” na pasku wiadomości");
  enqueueManual(async () => {
    let list = [];
    try {
      list = await displayedMessages(tab);
    } catch (e) {
      logEvent("click", false, "Nie udało się pobrać wyświetlanej wiadomości: " + errorText(e));
    }
    if (!list.length) {
      await feedback(false, "Nie znaleziono wyświetlanej wiadomości - nic nie zgłoszono.");
      return;
    }
    logEvent("click", true, "Wiadomości do zgłoszenia: " + list.length);
    for (const m of list) await reportSpamAndFile(m);
  }, "Zgłoś spam (przycisk)");
});

const MENU = {
  "antispam-spam": "Zgłoś jako spam (Antyspam)",
  "antispam-phishing": "Zgłoś próbę wyłudzenia / phishing (Antyspam)",
  "antispam-ham": "To nie spam (Antyspam)",
  "antispam-check": "Sprawdź w Antyspamie",
};
for (const [id, title] of Object.entries(MENU)) {
  messenger.menus.create({ id, title, contexts: ["message_list"], icons: { "32": "icons/icon-32.png" } });
}

/**
 * Messages a menu click applies to. info.selectedMessages is the usual
 * source; when it is missing or empty (seen in the field: the click did
 * nothing at all), the selection of the tab and then the displayed message
 * are used. `via` says where they came from (for the event log).
 */
async function selectedMessages(info, tab) {
  const out = [];
  let via = "";
  try {
    if (info && info.selectedMessages) {
      for await (const m of listMessages(info.selectedMessages)) out.push(m);
      if (out.length) via = "menu";
    }
  } catch (e) {
    logEvent("click", false, "Nie udało się odczytać zaznaczenia z menu: " + errorText(e));
  }
  if (!out.length && tab && messenger.mailTabs && messenger.mailTabs.getSelectedMessages) {
    try {
      for await (const m of listMessages(await step("zaznaczenie w karcie (mailTabs.getSelectedMessages)", () => messenger.mailTabs.getSelectedMessages(tab.id)))) out.push(m);
      if (out.length) via = "zaznaczenie w karcie";
    } catch (e) {
      logEvent("click", false, "Nie udało się odczytać zaznaczenia karty: " + errorText(e));
    }
  }
  if (!out.length && tab) {
    try {
      out.push(...await displayedMessages(tab));
      if (out.length) via = "wyświetlana wiadomość";
    } catch (e) { /* not a message tab */ }
  }
  return { messages: out, via };
}

messenger.menus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === RESCAN_MENU) return rescanClicked(info);
  if (!MENU[info.menuItemId]) return;
  logEvent("click", true, "Menu: " + MENU[info.menuItemId]);
  enqueueManual(async () => {
    const { messages, via } = await selectedMessages(info, tab);
    if (!messages.length) {
      await feedback(false, "Nic nie zaznaczono - zaznacz wiadomość na liście i spróbuj ponownie.", { menu: MENU[info.menuItemId] });
      return;
    }
    logEvent("click", true, "Zaznaczono wiadomości: " + messages.length + " (" + via + ")");
    for (const m of messages) {
      if (info.menuItemId === "antispam-spam") await reportSpamAndFile(m);
      else if (info.menuItemId === "antispam-phishing") await reportPhishing(m);
      else if (info.menuItemId === "antispam-ham") await reportHam(m);
      else await check(m, { manual: true });
    }
  }, MENU[info.menuItemId]);
});

/**
 * Menu titles say where a report of the clicked account goes; "To nie spam"
 * is greyed out for accounts that cannot send it (report_only).
 */
if (messenger.menus.onShown && messenger.menus.update) {
  messenger.menus.onShown.addListener(async (info) => {
    if (info && (info.menuIds || []).includes(RESCAN_MENU)) return rescanMenuShown(info);
    if (!info || !(info.menuIds || []).some(id => MENU[id])) return;
    try {
      let accountId = info.displayedFolder && info.displayedFolder.accountId;
      const first = info.selectedMessages && info.selectedMessages.messages && info.selectedMessages.messages[0];
      if (first && first.folder) accountId = first.folder.accountId;
      const ctx = await contextFor(accountId);
      const to = targetText(ctx);
      const hamOk = ctx.kind === "own" || ctx.kind === "linked";
      const checkOk = ctx.kind === "own" || ctx.kind === "linked";
      await messenger.menus.update("antispam-spam", { title: MENU["antispam-spam"] + " → " + to });
      await messenger.menus.update("antispam-phishing", { title: MENU["antispam-phishing"] + " → " + to });
      await messenger.menus.update("antispam-ham", {
        title: MENU["antispam-ham"] + (hamOk ? " → " + to : ctx.kind === "off" ? " – tylko lokalnie" : " – wymaga zalogowania tego konta"),
        enabled: hamOk || ctx.kind === "off",
      });
      await messenger.menus.update("antispam-check", {
        title: MENU["antispam-check"] + (checkOk ? " (" + to + ")" : " – wymaga zalogowania tego konta"),
        enabled: checkOk,
      });
      if (messenger.menus.refresh) await messenger.menus.refresh();
    } catch (e) {
      console.warn("antispam: menu update", e);
    }
  });
}

// --- full INBOX rescan on the server ("Sprawdź cały folder Odebrane") ----------

/*
 * A big INBOX (100 000 messages) is never read by Thunderbird: the plugin only
 * asks the server (POST /api/plugin/rescan) to check the whole INBOX of the
 * logged-in mailbox against the current rules. The server works in the
 * background, in batches, and moves spam to SPAM / QUARANTINE itself (never
 * deletes); Thunderbird just sees the messages leave INBOX. The plugin polls
 * GET /api/plugin/rescan and tells the user when it is finished. Pending
 * watches survive a Thunderbird restart (storage "rescanWatch").
 */
const RESCAN_MENU = "antispam-rescan";
const RESCAN_TITLE = "Sprawdź cały folder Odebrane na serwerze (Antyspam)";
const RESCAN_POLL_MS = 60 * 1000;
const RESCAN_WATCH_MAX_MS = 3 * 24 * 3600 * 1000;
const rescanTimers = new Map(); // login key → timer of the next poll

messenger.menus.create({ id: RESCAN_MENU, title: RESCAN_TITLE, contexts: ["folder_pane"], icons: { "32": "icons/icon-32.png" } });

/** Account of the folder a folder pane menu was opened on (TB 128+: selectedFolders, 115: selectedFolder). */
function menuFolderAccountId(info) {
  const f = (info && info.selectedFolders && info.selectedFolders[0]) || (info && info.selectedFolder) || (info && info.displayedFolder);
  return folderAccountId(f) || (info && info.selectedAccount && info.selectedAccount.id) || null;
}

function rescanCounters(last) {
  if (!last) return "";
  if (!last.ok) return "błąd: " + (last.error || "nieznany");
  const parts = ["sprawdzono " + (last.checked ?? last.total ?? 0)];
  if (last.moved_to_spam) parts.push("do SPAM: " + last.moved_to_spam);
  if (last.quarantined) parts.push("do kwarantanny: " + last.quarantined);
  if (last.move_failed) parts.push("nie udało się przenieść: " + last.move_failed);
  return parts.join(", ");
}

function rescanProgress(job) {
  if (!job) return "";
  if (job.total) return job.done + " z " + job.total + " (" + Math.floor(100 * job.done / Math.max(1, job.total)) + "%)";
  return job.progress || (job.status === "queued" ? "w kolejce na serwerze" : "w toku");
}

// Writes to "rescanWatch" run one after another (read-modify-write).
let rescanWrite = Promise.resolve();
function updateRescanWatch(fn) {
  rescanWrite = rescanWrite.then(async () => {
    const { rescanWatch = {} } = await messenger.storage.local.get("rescanWatch");
    fn(rescanWatch);
    await messenger.storage.local.set({ rescanWatch });
  }).catch(e => console.warn("antispam: rescan watch", e));
  return rescanWrite;
}

async function startRescan(accountId) {
  const ctx = await contextFor(accountId);
  if (ctx.kind !== "own") {
    await needsSetup("Sprawdzenie całego folderu Odebrane wymaga zalogowania tego konta (" + accountLabel(ctx.account) + ") we wtyczce jego skrzynką antyspamu.", contextDetail(ctx));
    return;
  }
  let res;
  try {
    res = await api("/api/plugin/rescan", { method: "POST", login: ctx.login, body: {} });
  } catch (e) {
    const text = e.status === 404 || e.status === 405
      ? "Serwer antyspamu nie obsługuje jeszcze sprawdzania całej skrzynki - zaktualizuj antyspam."
      : "Nie udało się zlecić sprawdzenia folderu Odebrane (" + ctx.login.email + "): " + errorText(e);
    await notify("Antyspam", text);
    await feedback(false, text, contextDetail(ctx));
    return;
  }
  const what = "folderu Odebrane skrzynki " + ctx.login.email;
  const text = res.created
    ? "Zlecono sprawdzenie całego " + what + ". Serwer robi to w tle i sam przenosi spam do folderu SPAM (nic nie usuwa) - możesz normalnie pracować, dam znać po zakończeniu."
    : "Sprawdzanie całego " + what + " już trwa: " + rescanProgress(res.job) + ".";
  await notify("Antyspam", text);
  await feedback(true, text, Object.assign(contextDetail(ctx), { zadanie: res.job ? "#" + res.job.id : "", postęp: rescanProgress(res.job) }));
  if (res.active) {
    await updateRescanWatch(w => { w[ctx.login.key] = { email: ctx.login.email, job: res.job ? res.job.id : null, t: Date.now(), progress: "" }; });
    scheduleRescanPoll(ctx.login.key, RESCAN_POLL_MS);
  }
}

function scheduleRescanPoll(key, ms) {
  clearTimeout(rescanTimers.get(key));
  rescanTimers.set(key, setTimeout(() => pollRescan(key).catch(e => logEvent("rescan", false, "Sprawdzanie postępu skanu: " + errorText(e))), ms));
}

async function pollRescan(key) {
  rescanTimers.delete(key);
  const { rescanWatch = {} } = await messenger.storage.local.get("rescanWatch");
  const watch = rescanWatch[key];
  if (!watch) return;
  const login = (await getLogins())[key];
  if (!login || Date.now() - watch.t > RESCAN_WATCH_MAX_MS) {
    logEvent("rescan", false, "Przestaję śledzić skan folderu Odebrane " + watch.email + (login ? " (trwa ponad 3 dni)" : " (wylogowano)") + " - stan w panelu antyspamu: Zadania w tle");
    await updateRescanWatch(w => { delete w[key]; });
    return;
  }
  let res;
  try {
    res = await api("/api/plugin/rescan", { login: Object.assign({ key }, login), quietOk: true });
  } catch (e) {
    // Server unreachable / restarting: try again later, a 401 already dropped the login.
    logEvent("rescan", false, "Skan folderu Odebrane " + watch.email + ": nie udało się odczytać postępu (" + errorText(e) + "), ponowię za " + Math.round(RESCAN_POLL_MS / 60000) + " min");
    scheduleRescanPoll(key, RESCAN_POLL_MS * 5);
    return;
  }
  if (res.active) {
    const progress = rescanProgress(res.job);
    if (progress !== watch.progress) {
      logEvent("rescan", true, "Skan folderu Odebrane " + watch.email + ": " + progress, res.job && res.job.progress ? res.job.progress : "");
      await updateRescanWatch(w => { if (w[key]) w[key].progress = progress; });
    }
    scheduleRescanPoll(key, RESCAN_POLL_MS);
    return;
  }
  await updateRescanWatch(w => { delete w[key]; });
  const ok = !!(res.last && res.last.ok);
  const text = "Zakończono sprawdzanie folderu Odebrane " + watch.email + (res.last ? ": " + rescanCounters(res.last) : "") + ".";
  await notify("Antyspam", text);
  await feedback(ok, text, res.last || "");
}

/** After a restart: go on watching rescans started before it. */
messenger.storage.local.get("rescanWatch").then(({ rescanWatch = {} }) => {
  for (const key of Object.keys(rescanWatch)) scheduleRescanPoll(key, 5000);
}).catch(() => {});

function rescanClicked(info) {
  const accountId = menuFolderAccountId(info);
  logEvent("click", true, "Menu folderu: " + RESCAN_TITLE, { konto: accountId || "?" });
  enqueueManual(async () => {
    if (!accountId) {
      await feedback(false, "Nie rozpoznano konta folderu - kliknij prawym przyciskiem folder Odebrane konta i spróbuj ponownie.");
      return;
    }
    await startRescan(accountId);
  }, RESCAN_TITLE);
}

/** Folder pane menu: the rescan entry is active for accounts logged in with their own mailbox. */
async function rescanMenuShown(info) {
  try {
    const ctx = await contextFor(menuFolderAccountId(info));
    const ok = ctx.kind === "own";
    await messenger.menus.update(RESCAN_MENU, {
      title: RESCAN_TITLE + (ok ? " → " + ctx.login.email : " – wymaga zalogowania tego konta"),
      enabled: ok,
    });
    if (messenger.menus.refresh) await messenger.menus.refresh();
  } catch (e) {
    console.warn("antispam: folder menu update", e);
  }
}

// --- connection test ("Testuj połączenie" on the settings page) --------------

/**
 * Step by step: server address, host permission, GET /status, then for each
 * tested login: GET /status with its token and POST /ping (which the server
 * writes to its audit log as plugin.ping). `target`: a Thunderbird account id,
 * "*" (general login), "all" (every login) or empty (default: every login,
 * anonymous when there is none). Returns {ok, steps: [{name, ok, text}]}.
 */
async function connectionTest(target) {
  const steps = [];
  const addStep = (name, ok, text) => { steps.push({ name, ok, text }); return ok; };
  const s = await settings();
  const manifest = messenger.runtime.getManifest();
  let app = "";
  try { const i = await step("wersja Thunderbirda", () => messenger.runtime.getBrowserInfo()); app = i.name + " " + i.version; } catch (e) { /* ignore */ }
  addStep("Wtyczka", true, "wersja " + manifest.version + (app ? ", " + app : "")
    + (s.bundledServer ? ", adres z pobranej wersji" : ", wersja ogólna (adres wpisany ręcznie)"));

  if (!addStep("Adres serwera", !!s.server, s.server || "nie ustawiono - wpisz adres w sekcji Serwer i zapisz")) {
    return finishTest(steps);
  }
  const origin = originPattern(s.server);
  if (!addStep("Poprawny adres", !!origin, origin ? s.server : "nieprawidłowy adres URL")) return finishTest(steps);
  let allowed = false;
  try { allowed = await step("sprawdzenie zgody (permissions.contains)", () => messenger.permissions.contains({ origins: [origin] })); } catch (e) { /* older API */ }
  addStep("Zgoda na połączenie z serwerem", allowed, allowed ? origin : "brak - kliknij „Zapisz ustawienia” i zaakceptuj prośbę Thunderbirda");

  let st;
  const t0 = Date.now();
  try {
    st = await api("/api/plugin/status", { timeout: 15000 });
    addStep("Serwer odpowiada (GET /status)", true, (Date.now() - t0) + " ms, serwer " + (st.server_version || "?") + ", wtyczka na serwerze " + (st.version || "?")
      + (st.version && st.version !== manifest.version ? " - pobierz nowszą wtyczkę" : ""));
    addStep("Wtyczki włączone na serwerze", !!st.enabled, st.enabled ? "tak" : "administrator wyłączył wtyczki");
    const foreign = { report_only: "tylko do administratora", linked: "jak podpięta skrzynka", off: "wyłączone" }[s.foreignMode];
    addStep("Konta bez logowania", s.foreignMode !== "report_only" || st.report_only === true,
      foreign + (s.foreignMode === "report_only" && st.report_only !== true ? " - serwer tego nie obsługuje (zaktualizuj antyspam): spam z takich kont idzie anonimowo, phishing nie jest wysyłany" : ""));
  } catch (e) {
    addStep("Serwer odpowiada (GET /status)", false, e.message);
    return finishTest(steps);
  }
  limitsCache = null;

  const logins = await getLogins();
  const accounts = await listAccounts();
  const label = key => key === GENERAL_LOGIN ? "logowanie ogólne" : ((accounts.find(a => a.id === key) || {}).name || key);
  let keys = Object.keys(logins);
  if (target && target !== "all") keys = keys.filter(k => k === target);
  if (target && target !== "all" && !keys.length) {
    addStep("Logowanie – " + label(target), false, "to konto nie jest zalogowane we wtyczce");
  }
  if (!keys.length) {
    addStep("Logowanie", true, "niezalogowano (działa tylko zgłaszanie spamu" + (st.anonymous_reports ? ")" : " - wyłączone na serwerze)"));
    await pingStep(addStep, null, "", manifest, app);
    return finishTest(steps);
  }
  for (const key of keys) {
    const login = Object.assign({ key }, logins[key]);
    const name = label(key);
    try {
      const ls = await api("/api/plugin/status", { timeout: 15000, login, quietOk: true });
      if (!ls.authenticated) {
        addStep("Logowanie – " + name, false, (login.email || "") + ": sesja wygasła - zaloguj się ponownie");
        await dropLogin(key, "sesja wygasła (test połączenia)");
        continue;
      }
      addStep("Logowanie – " + name, true, "zalogowano jako " + ls.email);
    } catch (e) {
      addStep("Logowanie – " + name, false, e.message);
      continue;
    }
    await pingStep(addStep, login, " – " + name, manifest, app);
  }
  return finishTest(steps);
}

async function pingStep(addStep, login, suffix, manifest, app) {
  try {
    const p = await api("/api/plugin/ping", { method: "POST", login, body: { client: "thunderbird", client_version: manifest.version, app } });
    addStep("Zapis testu na serwerze (POST /ping)" + suffix, !!p.ok, "przyjęto " + (p.received_at || "") + " z IP " + (p.client_ip || "?") + " - widoczne w panelu: Dziennik audytu, akcja plugin.ping");
  } catch (e) {
    addStep("Zapis testu na serwerze (POST /ping)" + suffix, false, e.message + (e.status === 404 ? " - serwer nie ma jeszcze tej funkcji (zaktualizuj antyspam)" : ""));
  }
}

async function finishTest(steps) {
  const ok = steps.every(x => x.ok);
  await logEvent("test", ok, "Test połączenia: " + (ok ? "OK" : steps.filter(x => !x.ok).map(x => x.name).join(", ")),
    steps.map(x => (x.ok ? "✓ " : "✗ ") + x.name + (x.text ? " — " + x.text : "")).join("\n"));
  return { ok, steps };
}

// --- options page bridge ----------------------------------------------------

/** Accounts for the settings page: Thunderbird accounts + their login state (no tokens). */
async function accountsState() {
  const s = await settings();
  const logins = await getLogins();
  const accounts = await listAccounts();
  const def = await defaultLogin(logins, accounts);
  const view = l => l ? { email: l.email, expires_at: l.expires_at || null } : null;
  const rows = accounts.map(a => ({ id: a.id, name: a.name, emails: a.emails, login: view(logins[a.id]) }));
  const known = new Set(accounts.map(a => a.id));
  for (const key of Object.keys(logins)) {
    if (key === GENERAL_LOGIN) {
      rows.push({ id: GENERAL_LOGIN, name: "Logowanie ogólne (bez konta w Thunderbirdzie)", emails: [], login: view(logins[key]), general: true });
    } else if (!known.has(key)) {
      rows.push({ id: key, name: "Usunięte konto Thunderbirda (" + key + ")", emails: [], login: view(logins[key]), orphan: true });
    }
  }
  return { accounts: rows, foreignMode: s.foreignMode, defaultLogin: def ? { key: def.key, email: def.email } : null };
}

messenger.runtime.onMessage.addListener(async (msg) => {
  switch (msg && msg.cmd) {
    case "settings": {
      const s = await settings();
      // Compatibility with the 1.2 page fields: e-mail of the default login.
      const def = await defaultLogin(await getLogins());
      s.email = def ? def.email : "";
      return s;
    }
    case "accounts":
      return accountsState();
    case "status": {
      const res = await api("/api/plugin/status", { quietOk: true });
      // /status answers 200 {"authenticated": false} for an expired / unknown
      // token (never 401): drop such logins here, so the page shows their login form.
      const logins = await getLogins();
      res.logged_out = [];
      for (const key of Object.keys(logins)) {
        try {
          const ls = await api("/api/plugin/status", { login: Object.assign({ key }, logins[key]), quietOk: true });
          if (!ls.authenticated) {
            await dropLogin(key, "sesja wygasła");
            res.logged_out.push(logins[key].email);
          }
        } catch (e) { /* server unreachable - keep the login */ }
      }
      limitsCache = null;
      return res;
    }
    case "login": {
      const key = String(msg.accountId || "");
      if (!key) throw new Error("Nie wybrano konta Thunderbirda.");
      const res = await api("/api/plugin/login", {
        method: "POST", body: { email: msg.email, password: msg.password },
      });
      await updateLogins(l => { l[key] = { token: res.token, email: res.email, expires_at: res.expires_at || null }; });
      const acc = (await listAccounts()).find(a => a.id === key);
      logEvent("login", true, "Zalogowano " + res.email + (acc ? " na koncie " + acc.name : ""),
        acc && !acc.emails.includes(String(res.email).toLowerCase()) ? "Uwaga: " + res.email + " nie jest adresem tego konta (" + acc.emails.join(", ") + ")" : "");
      return { email: res.email, expires_at: res.expires_at || null };
    }
    case "logout": {
      const key = String(msg.accountId || "");
      const logins = await getLogins();
      if (logins[key]) {
        await updateLogins(l => { delete l[key]; });
        logEvent("login", true, "Wylogowano " + (logins[key].email || "") + " (na żądanie)");
      }
      return { ok: true };
    }
    case "test":
      return connectionTest(msg.accountId || "");
    case "events": {
      const { eventLog = [] } = await messenger.storage.local.get("eventLog");
      return eventLog;
    }
    case "clearEvents":
      await messenger.storage.local.set({ eventLog: [] });
      return { ok: true };
    default:
      return undefined;
  }
});

// Move a 1.2.x login to its account as soon as the plugin starts.
migrateLegacyLogin();
