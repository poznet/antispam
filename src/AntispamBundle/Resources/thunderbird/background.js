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
// attachments past this point are cut off.
const MAX_UPLOAD_BYTES = 1024 * 1024;
// Phishing reports carry the whole message (attachments too) up to this size
// (PhishingReportService::MAX_RAW_BYTES on the server).
const MAX_PHISHING_BYTES = 10 * 1024 * 1024;
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

// --- settings / API ---------------------------------------------------------

async function settings() {
  const s = Object.assign({}, DEFAULTS, await messenger.storage.local.get(Object.keys(DEFAULTS)));
  if (!s.server) s.server = await bundledServer;
  s.server = (s.server || "").replace(/\/+$/, "");
  return s;
}

async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const s = await settings();
  if (!s.server) throw new Error("Nie ustawiono adresu serwera antyspamu (Ustawienia wtyczki).");
  const headers = { "Accept": "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (auth && s.token) headers["Authorization"] = "Bearer " + s.token;

  const res = await fetch(s.server + path, {
    method,
    headers,
    body: body === null ? null : JSON.stringify(body),
    credentials: "omit",
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (res.status === 401 && s.token && auth) {
    // Token expired or account removed — fall back to anonymous mode.
    await messenger.storage.local.set({ token: "", email: "" });
  }
  if (!res.ok) {
    const err = new Error(data.error || ("HTTP " + res.status));
    err.status = res.status;
    throw err;
  }
  return data;
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

/** Raw source as base64, cut at `limit` bytes; `truncated` tells whether it was. */
async function rawSource(messageId, limit = MAX_UPLOAD_BYTES) {
  let raw = await messenger.messages.getRaw(messageId);
  let bin;
  let size;
  if (typeof raw === "string") {
    size = raw.length;
    bin = raw.length > limit ? raw.slice(0, limit) : raw;
  } else {
    // Newer Thunderbird may hand back a File/Blob.
    size = raw.size;
    const buf = new Uint8Array(await raw.slice(0, limit).arrayBuffer());
    bin = "";
    for (let i = 0; i < buf.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    }
  }
  return { base64: btoa(bin), truncated: size > limit };
}

async function rawBase64(messageId) {
  return (await rawSource(messageId)).base64;
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
    await messenger.messages.move([message.id], junk);
    return true;
  } catch (e) {
    console.warn("antispam: move to junk failed", e);
    return false;
  }
}

// --- actions ----------------------------------------------------------------

/** Send a user verdict ("spam" | "ham") to antispam. */
async function report(message, verdict, { quiet = false, manual = false } = {}) {
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
  try {
    const res = await api("/api/plugin/report", {
      method: "POST",
      body: { verdict, raw_base64: await rawBase64(message.id) },
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
    const text = "Nie udało się wysłać zgłoszenia do " + s.server + ": " + e.message;
    if (!quiet) await notify("Antyspam — błąd", text);
    if (manual) await feedback(false, text);
    return null;
  }
}

/** Report as spam from the button / menu and handle the message locally. */
async function reportSpamAndFile(message) {
  await report(message, "spam", { manual: true });
  const s = await settings();
  await setJunk(message, true);
  if (s.moveOnReport) await moveToJunk(message);
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
  try {
    const src = await rawSource(message.id, MAX_PHISHING_BYTES);
    const res = await api("/api/plugin/phishing", {
      method: "POST",
      body: { raw_base64: src.base64, truncated: src.truncated, client: "thunderbird" },
    });
    const text = "Zgłoszono próbę wyłudzenia: " + (message.author || res.sender || "")
      + (res.duplicate ? " (już była zgłoszona)" : "") + (res.rules && res.rules.length ? " – nadawca zablokowany" : "");
    await notify("Antyspam", text);
    await feedback(true, text);
  } catch (e) {
    console.warn("antispam: phishing report failed", e);
    const text = "Nie udało się zgłosić phishingu do " + s.server + ": " + e.message;
    await notify("Antyspam — błąd", text);
    await feedback(false, text);
    return;
  }
  await setJunk(message, true);
  if (s.moveOnReport) await moveToJunk(message);
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
    res = await api("/api/plugin/check", { method: "POST", body: { raw_base64: await rawBase64(message.id) } });
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

let queue = Promise.resolve();

function enqueue(fn) {
  queue = queue.then(fn).catch(e => console.warn("antispam:", e));
  return queue;
}

async function* listMessages(list) {
  let page = list;
  while (page) {
    for (const m of page.messages) yield m;
    page = page.id ? await messenger.messages.continueList(page.id) : null;
  }
}

messenger.messages.onNewMailReceived.addListener((folder, messageList) => {
  enqueue(async () => {
    const now = Date.now();
    const s = await settings();
    const checkThis = s.token && s.autoCheck
      && (await accountEmails(folderAccountId(folder))).includes((s.email || "").toLowerCase());

    for await (const message of listMessages(messageList)) {
      arrivals.set(message.id, now);
      if (checkThis) await check(message);
    }
    for (const [id, t] of arrivals) if (now - t > ARRIVAL_GRACE_MS) arrivals.delete(id);
  });
});

// Thunderbird's own junk / not-junk buttons.
if (messenger.messages.onUpdated) {
  messenger.messages.onUpdated.addListener((message, changed) => {
    if (!changed || typeof changed.junk !== "boolean") return;
    if (ownChanges.has(message.id)) return;
    const arrived = arrivals.get(message.id);
    if (arrived && Date.now() - arrived < ARRIVAL_GRACE_MS) return; // automatic classifier
    enqueue(async () => {
      const s = await settings();
      if (!s.reportOnJunk) return;
      if (changed.junk) await report(message, "spam");
      else if (s.token) await report(message, "ham");
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
  enqueue(async () => {
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
  enqueue(async () => {
    for (const m of await selectedMessages(info)) {
      if (info.menuItemId === "antispam-spam") await reportSpamAndFile(m);
      else if (info.menuItemId === "antispam-phishing") await reportPhishing(m);
      else if (info.menuItemId === "antispam-ham") await reportHam(m);
      else await check(m, { manual: true });
    }
  });
});

// --- options page bridge ----------------------------------------------------

messenger.runtime.onMessage.addListener(async (msg) => {
  switch (msg && msg.cmd) {
    case "settings":
      return settings();
    case "status":
      return api("/api/plugin/status");
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
    default:
      return undefined;
  }
});
