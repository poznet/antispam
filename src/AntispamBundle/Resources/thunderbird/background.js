/*
 * Antispam Pancernapanda — Thunderbird plugin (background script).
 *
 * Not logged in: marking a message as junk (Thunderbird's own junk button, the
 * toolbar button or the context menu) reports it to antispam, which records
 * its fingerprints in the shared spam DB.
 *
 * Logged in (mailbox e-mail + plugin/IMAP password): reports also teach the
 * account's rules (spam → blacklist, not-spam → whitelist), and every new
 * message arriving to that mailbox can be sent to antispam for a check; the
 * plugin then marks / moves it according to the decision.
 *
 * Logged in, "Zgłoś phishing" sends the whole message (attachments included,
 * up to the server's limit) for the admin to inspect, and files it as junk.
 *
 * Server API: docs/thunderbird.md (/api/plugin/*).
 */

"use strict";

const DEFAULTS = {
  server: "",           // base URL of the antispam instance (from config.json when empty)
  token: "",
  email: "",
  autoCheck: true,      // logged in: check new mail on arrival
  reportOnJunk: true,   // report when the user marks a message as junk / not junk
  spamAction: "move",   // move | mark | none
  quarantineAction: "none", // move | mark | none
  moveOnReport: true,   // move to Junk after reporting from the button / menu
  notify: true,
};

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
// Thunderbird's own junk classifier flags messages right after they arrive;
// junk changes within this window of arrival are not treated as user verdicts.
const ARRIVAL_GRACE_MS = 2 * 60 * 1000;

// Server URL baked into config.json by the antispam download endpoint.
const bundledServer = fetch(messenger.runtime.getURL("config.json"))
  .then(r => r.json())
  .then(c => (c.server || "").replace(/\/+$/, ""))
  .catch(() => "");
const BUTTON_TITLE = "Zgłoś spam (Antyspam)";
const ownChanges = new Set();   // message ids whose junk flag we changed ourselves
const arrivals = new Map();     // message id → arrival timestamp
const movedTo = new Map();      // old message id → { id, t } after a move (onMoved)

// --- settings / API ---------------------------------------------------------

// --- event log (shown on the settings page, "Diagnostyka") -----------------

const EVENT_LOG_MAX = 40;
let eventWrite = Promise.resolve();

/** Remember what the plugin did (clicks, requests, errors) - readable on the settings page. */
function logEvent(kind, ok, text) {
  const entry = { t: Date.now(), kind, ok: !!ok, text: String(text || "").slice(0, 300) };
  eventWrite = eventWrite.then(async () => {
    const { eventLog = [] } = await messenger.storage.local.get("eventLog");
    eventLog.unshift(entry);
    await messenger.storage.local.set({ eventLog: eventLog.slice(0, EVENT_LOG_MAX) });
  }).catch(e => console.warn("antispam: event log", e));
  return eventWrite;
}

async function settings() {
  const s = Object.assign({}, DEFAULTS, await messenger.storage.local.get(Object.keys(DEFAULTS)));
  if (!s.server) s.server = await bundledServer;
  s.server = (s.server || "").replace(/\/+$/, "");
  return s;
}

async function api(path, { method = "GET", body = null, auth = true, timeout = REQUEST_TIMEOUT_MS } = {}) {
  const s = await settings();
  if (!s.server) throw new Error("Nie ustawiono adresu serwera antyspamu (Ustawienia wtyczki).");
  const headers = { "Accept": "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (auth && s.token) headers["Authorization"] = "Bearer " + s.token;

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
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
      logEvent("api", false, method + " " + path + ": " + err.message);
      throw err;
    }
    logEvent("api", false, method + " " + path + ": " + e.message + " (brak połączenia, uprawnienia lub certyfikat)");
    throw new Error(e.message);
  } finally {
    clearTimeout(timer);
  }
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (res.status === 401 && s.token && auth) {
    // Token expired or account removed — fall back to anonymous mode.
    await messenger.storage.local.set({ token: "", email: "" });
  }
  if (!res.ok) {
    const err = new Error(data.message || data.error
      || (res.status === 413 ? "wiadomość za duża dla serwera (HTTP 413)" : "HTTP " + res.status));
    err.status = res.status;
    logEvent("api", false, method + " " + path + ": " + (data.error ? "HTTP " + res.status + " " + data.error : err.message));
    throw err;
  }
  if (path !== "/api/plugin/status") logEvent("api", true, method + " " + path + ": HTTP " + res.status);
  return data;
}

/**
 * Upload limits published by the server (max_upload_bytes, phishing_max_bytes).
 * Cached; on any error the built-in defaults are used.
 */
let limitsCache = null;
async function serverLimits() {
  const s = await settings();
  if (limitsCache && limitsCache.server === s.server && Date.now() - limitsCache.t < limitsCache.ttl) {
    return limitsCache.limits;
  }
  const limits = { maxUpload: MAX_UPLOAD_BYTES, phishingMax: MAX_PHISHING_BYTES, known: false };
  let ttl = LIMITS_TTL_MS;
  try {
    const st = await api("/api/plugin/status", { timeout: LIMITS_TIMEOUT_MS });
    const max = Number(st.max_upload_bytes);
    if (Number.isFinite(max) && max >= 16 * 1024) {
      limits.maxUpload = max;
      limits.known = true;
    }
    const pmax = Number(st.phishing_max_bytes);
    if (Number.isFinite(pmax) && pmax > 0) limits.phishingMax = pmax;
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

async function notify(title, message) {
  const s = await settings();
  if (!s.notify) return;
  try {
    await messenger.notifications.create({
      type: "basic",
      iconUrl: messenger.runtime.getURL("icons/icon-64.png"),
      title,
      message,
    });
  } catch (e) { console.warn("antispam: notification failed", e); }
}

/**
 * Result of an explicit action (button / menu) on the toolbar button, so the
 * user sees something even when system notifications are off.
 */
let badgeTimer = null;
async function feedback(ok, text) {
  const btn = messenger.messageDisplayAction;
  try {
    await btn.setBadgeText({ text: ok ? "✓" : "!" });
    await btn.setBadgeBackgroundColor({ color: ok ? "#2e7d32" : "#c62828" });
    await btn.setTitle({ title: "Antyspam: " + text });
  } catch (e) { /* older Thunderbird */ }
  clearTimeout(badgeTimer);
  badgeTimer = setTimeout(() => {
    btn.setBadgeText({ text: "" }).catch(() => {});
    btn.setTitle({ title: BUTTON_TITLE }).catch(() => {});
  }, 30000);
}

/** Explicit action that cannot run as configured: tell the user and open the settings. */
async function needsSetup(text) {
  await notify("Antyspam", text);
  await feedback(false, text);
  try { await messenger.runtime.openOptionsPage(); } catch (e) { /* ignore */ }
}

// --- message helpers --------------------------------------------------------

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
  return { base64: btoa(bin), truncated: size > limit };
}

/** Raw source of a message as base64, cut at `limit` bytes. */
async function rawSource(messageId, limit = MAX_UPLOAD_BYTES) {
  return encodeRaw(await messenger.messages.getRaw(messageId), limit);
}

async function rawBase64(messageId, limit = MAX_UPLOAD_BYTES) {
  return (await rawSource(messageId, limit)).base64;
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
    return messenger.messages.getRaw(moved.id);
  }
}

async function accountEmails(accountId) {
  try {
    const acc = await messenger.accounts.get(accountId);
    return (acc && acc.identities ? acc.identities : []).map(i => (i.email || "").toLowerCase());
  } catch (e) {
    return [];
  }
}

function folderAccountId(folder) {
  return folder && folder.accountId;
}

async function findJunkFolder(accountId) {
  try {
    if (messenger.folders && messenger.folders.query) {
      const found = await messenger.folders.query({ accountId, specialUse: ["junk"] });
      if (found && found.length) return found[0];
    }
  } catch (e) { /* older Thunderbird */ }

  try {
    const acc = await messenger.accounts.get(accountId, true);
    const stack = [...((acc && acc.folders) || [])];
    while (stack.length) {
      const f = stack.shift();
      if ((f.specialUse || []).includes("junk") || f.type === "junk") return f;
      stack.push(...(f.subFolders || []));
    }
  } catch (e) { /* ignore */ }
  return null;
}

async function setJunk(message, junk) {
  ownChanges.add(message.id);
  try {
    await messenger.messages.update(message.id, { junk });
  } catch (e) {
    console.warn("antispam: could not set junk flag", e);
  } finally {
    setTimeout(() => ownChanges.delete(message.id), 10000);
  }
}

async function moveToJunk(message) {
  const junk = await findJunkFolder(folderAccountId(message.folder));
  if (!junk) return false;
  if (message.folder && junk.path === message.folder.path) return true;
  try {
    // Thunderbird 121+ takes the folder id (the MailFolder object is deprecated
    // and gone in MV3); 115 has no folder ids and needs the object.
    await messenger.messages.move([message.id], junk.id || junk);
    return true;
  } catch (e) {
    console.warn("antispam: move to junk failed", e);
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
  if (verdict === "ham" && !s.token) {
    const text = "Zgłoszenie „to nie spam” wymaga zalogowania we wtyczce.";
    if (manual) await needsSetup(text);
    else if (!quiet) await notify("Antyspam", text);
    return null;
  }
  if (!s.server) {
    const text = "Nie ustawiono adresu serwera antyspamu.";
    if (manual) await needsSetup(text);
    else if (!quiet) await notify("Antyspam — błąd", text);
    return null;
  }
  let raw;
  try {
    const limit = await reportLimit();
    raw = rawData
      ? (await encodeRaw(await rawAfterMove(message, rawData), limit)).base64
      : await rawBase64(message.id, limit);
  } catch (e) {
    console.warn("antispam: could not read message", e);
    const text = "Nie udało się odczytać wiadomości do zgłoszenia: " + e.message;
    if (!quiet) await notify("Antyspam — błąd", text);
    if (manual) await feedback(false, text);
    return null;
  }
  try {
    const res = await api("/api/plugin/report", {
      method: "POST",
      body: { verdict, raw_base64: raw },
    });
    const who = message.author || res.sender || "";
    const text = verdict === "spam"
      ? "Zgłoszono spam: " + who + (res.rules && res.rules.length ? " (nadawca zablokowany)" : "")
      : "Oznaczono jako nie-spam: " + who + (res.rules && res.rules.length ? " (nadawca na białej liście)" : "");
    if (!quiet) await notify("Antyspam", text);
    if (manual) await feedback(true, text);
    return res;
  } catch (e) {
    console.warn("antispam: report failed", e);
    if (e.timeout) {
      // The server stores the report before it answers; a timeout almost
      // always means it is still busy, not that the report was lost.
      const text = "Serwer " + s.server + " nie odpowiedział na czas – zgłoszenie prawdopodobnie zostało przyjęte.";
      if (!quiet) await notify("Antyspam", text);
      if (manual) await feedback(true, text);
      return null;
    }
    const text = "Nie udało się wysłać zgłoszenia do " + s.server + ": " + e.message;
    if (!quiet) await notify("Antyspam — błąd", text);
    if (manual) await feedback(false, text);
    return null;
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
  try { raw = await messenger.messages.getRaw(message.id); } catch (e) { console.warn("antispam: could not read message", e); }
  await fileAsJunk(message);
  if (raw !== null) await report(message, "spam", { manual: true, rawData: Promise.resolve(raw) });
  else await feedback(false, "Nie udało się odczytać wiadomości do zgłoszenia.");
}

/**
 * Logged in only: report a phishing attempt. The server keeps the whole
 * message for the admin and treats it as a spam report; locally it is filed
 * as junk like "Zgłoś spam".
 */
async function reportPhishing(message) {
  const s = await settings();
  if (!s.token) {
    await needsSetup("Zgłoszenie phishingu wymaga zalogowania we wtyczce (wiadomość trafia w całości do administratora).");
    return;
  }
  // Read now: the move below changes the message id.
  let raw;
  try {
    raw = await messenger.messages.getRaw(message.id);
  } catch (e) {
    await feedback(false, "Nie udało się odczytać wiadomości: " + e.message);
    return;
  }
  await fileAsJunk(message);
  const send = (body) => api("/api/plugin/phishing", { method: "POST", body, timeout: UPLOAD_TIMEOUT_MS });
  try {
    // As much of the message as the server (and the proxy in front of it) accepts.
    const limits = await serverLimits();
    const limit = Math.min(limits.phishingMax, limits.known ? limits.maxUpload : MAX_PHISHING_BYTES);
    const src = await encodeRaw(raw, limit);
    let res;
    try {
      res = await send({ raw_base64: src.base64, truncated: src.truncated, client: "thunderbird" });
    } catch (e) {
      const fallback = Math.min(MAX_UPLOAD_BYTES, limit);
      // Nothing to gain when what was sent is no bigger than the fallback.
      if (e.status !== 413 || src.base64.length <= Math.ceil(fallback / 3) * 4) throw e;
      // A proxy in front of antispam still limits the body size: send the head of the message.
      res = await send({ raw_base64: (await encodeRaw(raw, fallback)).base64, truncated: true, client: "thunderbird" });
    }
    const text = "Zgłoszono próbę wyłudzenia: " + (message.author || res.sender || "")
      + (res.duplicate ? " (już była zgłoszona)" : "") + (res.rules && res.rules.length ? " – nadawca zablokowany" : "");
    await notify("Antyspam", text);
    await feedback(true, text);
  } catch (e) {
    console.warn("antispam: phishing report failed", e);
    if (e.timeout) {
      // Unlike a spam report the upload itself may have stalled, so only "may have".
      const text = "Serwer " + s.server + " nie odpowiedział na czas – zgłoszenie phishingu mogło zostać przyjęte; sprawdź u administratora, zanim zgłosisz je ponownie.";
      await notify("Antyspam", text);
      await feedback(false, text);
      return;
    }
    const text = "Nie udało się zgłosić phishingu do " + s.server + ": " + e.message;
    await notify("Antyspam — błąd", text);
    await feedback(false, text);
  }
}

async function reportHam(message) {
  const res = await report(message, "ham", { manual: true });
  if (res) await setJunk(message, false);
}

/** Logged in only: ask antispam to score a message and act on the decision. */
async function check(message, { manual = false } = {}) {
  const s = await settings();
  if (!s.token) {
    if (manual) await needsSetup("Sprawdzanie wiadomości wymaga zalogowania we wtyczce (adres skrzynki + hasło wtyczki lub IMAP).");
    return null;
  }
  let res;
  try {
    res = await api("/api/plugin/check", { method: "POST", body: { raw_base64: await rawBase64(message.id, await reportLimit()) } });
  } catch (e) {
    console.warn("antispam: check failed", e);
    if (manual) {
      const text = "Sprawdzenie nie powiodło się (" + s.server + "): " + e.message;
      await notify("Antyspam — błąd", text);
      await feedback(false, text);
    }
    return null;
  }

  const action = res.decision === "spam" ? s.spamAction
    : res.decision === "quarantine" ? s.quarantineAction : "none";
  if (action === "mark" || action === "move") await setJunk(message, true);
  if (action === "move") await moveToJunk(message);

  if (manual || res.decision === "spam") {
    const labels = { spam: "SPAM", quarantine: "podejrzana", ham: "czysta", whitelisted: "biała lista" };
    const label = labels[res.decision] || res.decision;
    const text = (message.subject || "(bez tematu)") + " — wynik " + res.score + "/" + res.spam_threshold;
    await notify("Antyspam: " + label, text);
    if (manual) await feedback(true, label + ": " + text);
  }
  return res;
}

// --- new mail ---------------------------------------------------------------

// Automatic work (on-arrival checks, Thunderbird's junk button) runs one at a
// time; the user's own clicks have a queue of their own so they never wait
// behind a batch of new-mail checks.
let queue = Promise.resolve();
let manualQueue = Promise.resolve();

function enqueue(fn) {
  queue = queue.then(fn).catch(e => console.warn("antispam:", e));
  return queue;
}

function enqueueManual(fn) {
  manualQueue = manualQueue.then(fn).catch(e => console.warn("antispam:", e));
  return manualQueue;
}

async function* listMessages(list) {
  let page = list;
  while (page) {
    for (const m of page.messages) yield m;
    page = page.id ? await messenger.messages.continueList(page.id) : null;
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
    const checkThis = s.token && s.autoCheck
      && (await accountEmails(folderAccountId(folder))).includes((s.email || "").toLowerCase());

    for await (const message of listMessages(messageList)) {
      if (!arrivals.has(message.id)) arrivals.set(message.id, now); // later pages
      if (checkThis) await check(message);
    }
  });
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
    const rawData = messenger.messages.getRaw(message.id);
    rawData.catch(() => {}); // handled in report(); avoids an unhandled rejection meanwhile
    logEvent("junk", true, (changed.junk ? "Oznaczono jako śmieci" : "Oznaczono jako nie-śmieci") + " w Thunderbirdzie: " + (message.subject || "(bez tematu)"));
    enqueue(async () => {
      const s = await settings();
      if (!s.reportOnJunk) {
        logEvent("junk", false, "Zgłaszanie przy oznaczaniu śmieci jest wyłączone w ustawieniach");
        return;
      }
      if (changed.junk) await report(message, "spam", { rawData });
      else if (s.token) await report(message, "ham", { rawData });
    });
  });
}

// --- UI: toolbar button + context menu --------------------------------------

async function displayedMessages(tab) {
  if (messenger.messageDisplay.getDisplayedMessages) {
    const r = await messenger.messageDisplay.getDisplayedMessages(tab.id);
    return Array.isArray(r) ? r : (r && r.messages) || [];
  }
  const m = await messenger.messageDisplay.getDisplayedMessage(tab.id);
  return m ? [m] : [];
}

messenger.messageDisplayAction.onClicked.addListener(tab => {
  logEvent("click", true, "Przycisk „Zgłoś spam” na pasku wiadomości");
  enqueueManual(async () => {
    for (const m of await displayedMessages(tab)) await reportSpamAndFile(m);
  });
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

async function selectedMessages(info) {
  const out = [];
  if (info.selectedMessages) {
    for await (const m of listMessages(info.selectedMessages)) out.push(m);
  }
  return out;
}

messenger.menus.onClicked.addListener(info => {
  if (!MENU[info.menuItemId]) return;
  logEvent("click", true, "Menu: " + MENU[info.menuItemId]);
  enqueueManual(async () => {
    for (const m of await selectedMessages(info)) {
      if (info.menuItemId === "antispam-spam") await reportSpamAndFile(m);
      else if (info.menuItemId === "antispam-phishing") await reportPhishing(m);
      else if (info.menuItemId === "antispam-ham") await reportHam(m);
      else await check(m, { manual: true });
    }
  });
});

// --- connection test ("Testuj połączenie" on the settings page) --------------

/**
 * Step by step: server address, host permission, GET /status, POST /ping (which
 * the server writes to its audit log as plugin.ping). Returns a list of
 * {name, ok, text} for the settings page.
 */
async function connectionTest() {
  const steps = [];
  const step = (name, ok, text) => { steps.push({ name, ok, text }); return ok; };
  const s = await settings();
  const manifest = messenger.runtime.getManifest();
  let app = "";
  try { const i = await messenger.runtime.getBrowserInfo(); app = i.name + " " + i.version; } catch (e) { /* ignore */ }
  step("Wtyczka", true, "wersja " + manifest.version + (app ? ", " + app : ""));

  if (!step("Adres serwera", !!s.server, s.server || "nie ustawiono - wpisz adres w sekcji Serwer i zapisz")) {
    return finishTest(steps);
  }
  let origin = null;
  try { const u = new URL(s.server); origin = u.protocol + "//" + u.hostname + "/*"; } catch (e) { /* invalid */ }
  if (!step("Poprawny adres", !!origin, origin ? s.server : "nieprawidłowy adres URL")) return finishTest(steps);
  let allowed = false;
  try { allowed = await messenger.permissions.contains({ origins: [origin] }); } catch (e) { /* older API */ }
  step("Zgoda na połączenie z serwerem", allowed, allowed ? origin : "brak - kliknij „Zapisz ustawienia” i zaakceptuj prośbę Thunderbirda");

  let st;
  const t0 = Date.now();
  try {
    st = await api("/api/plugin/status", { timeout: 15000 });
    step("Serwer odpowiada (GET /status)", true, (Date.now() - t0) + " ms, serwer " + (st.server_version || "?") + ", wtyczka na serwerze " + (st.version || "?")
      + (st.version && st.version !== manifest.version ? " - pobierz nowszą wtyczkę" : ""));
    step("Wtyczki włączone na serwerze", !!st.enabled, st.enabled ? "tak" : "administrator wyłączył wtyczki");
    step("Logowanie", !!st.authenticated || !s.token, st.authenticated ? "zalogowano jako " + st.email
      : (s.token ? "sesja wygasła - zaloguj się ponownie" : "niezalogowano (działa tylko zgłaszanie spamu" + (st.anonymous_reports ? ")" : " - wyłączone na serwerze)")));
  } catch (e) {
    step("Serwer odpowiada (GET /status)", false, e.message);
    return finishTest(steps);
  }

  try {
    const p = await api("/api/plugin/ping", { method: "POST", body: { client: "thunderbird", client_version: manifest.version, app } });
    step("Zapis testu na serwerze (POST /ping)", !!p.ok, "przyjęto " + (p.received_at || "") + " z IP " + (p.client_ip || "?") + " - widoczne w panelu: Dziennik audytu, akcja plugin.ping");
  } catch (e) {
    step("Zapis testu na serwerze (POST /ping)", false, e.message + (e.status === 404 ? " - serwer nie ma jeszcze tej funkcji (zaktualizuj antyspam)" : ""));
  }
  return finishTest(steps);
}

async function finishTest(steps) {
  const ok = steps.every(x => x.ok);
  await logEvent("test", ok, "Test połączenia: " + (ok ? "OK" : steps.filter(x => !x.ok).map(x => x.name).join(", ")));
  return { ok, steps };
}

// --- options page bridge ----------------------------------------------------

messenger.runtime.onMessage.addListener(async (msg) => {
  switch (msg && msg.cmd) {
    case "settings":
      return settings();
    case "status": {
      const s = await settings();
      const res = await api("/api/plugin/status");
      // /status answers 200 {"authenticated": false} for an expired / unknown
      // token (never 401): log out once here, so the page shows the login form.
      if (s.token && !res.authenticated) {
        await messenger.storage.local.set({ token: "", email: "" });
        res.logged_out = true;
      }
      limitsCache = null;
      return res;
    }
    case "login": {
      const res = await api("/api/plugin/login", {
        method: "POST", auth: false, body: { email: msg.email, password: msg.password },
      });
      await messenger.storage.local.set({ token: res.token, email: res.email });
      return res;
    }
    case "logout":
      await messenger.storage.local.set({ token: "", email: "" });
      return { ok: true };
    case "test":
      return connectionTest();
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
