/*
 * Pancernapanda Antyspam — Thunderbird plugin (background script).
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
// Thunderbird's own junk classifier flags messages right after they arrive;
// junk changes within this window of arrival are not treated as user verdicts.
const ARRIVAL_GRACE_MS = 2 * 60 * 1000;

// Server URL baked into config.json by the antispam download endpoint.
const bundledServer = fetch(messenger.runtime.getURL("config.json"))
  .then(r => r.json())
  .then(c => (c.server || "").replace(/\/+$/, ""))
  .catch(() => "");
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
      iconUrl: messenger.runtime.getURL("icons/icon.svg"),
      title,
      message,
    });
  } catch (e) { console.warn("antispam: notification failed", e); }
}

// --- message helpers --------------------------------------------------------

/** Raw source as base64 (truncated to MAX_UPLOAD_BYTES). */
async function rawBase64(messageId) {
  let raw = await messenger.messages.getRaw(messageId);
  let bin;
  if (typeof raw === "string") {
    bin = raw.length > MAX_UPLOAD_BYTES ? raw.slice(0, MAX_UPLOAD_BYTES) : raw;
  } else {
    // Newer Thunderbird may hand back a File/Blob.
    const buf = new Uint8Array(await raw.slice(0, MAX_UPLOAD_BYTES).arrayBuffer());
    bin = "";
    for (let i = 0; i < buf.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
    }
  }
  return btoa(bin);
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
async function report(message, verdict, { quiet = false } = {}) {
  const s = await settings();
  if (verdict === "ham" && !s.token) {
    if (!quiet) await notify("Antyspam", "Zgłoszenie „to nie spam” wymaga zalogowania we wtyczce.");
    return null;
  }
  try {
    const res = await api("/api/plugin/report", {
      method: "POST",
      body: { verdict, raw_base64: await rawBase64(message.id) },
    });
    if (!quiet) {
      const who = message.author || res.sender || "";
      await notify("Antyspam",
        verdict === "spam"
          ? "Zgłoszono spam: " + who + (res.rules && res.rules.length ? " (nadawca zablokowany)" : "")
          : "Oznaczono jako nie-spam: " + who + (res.rules && res.rules.length ? " (nadawca na białej liście)" : ""));
    }
    return res;
  } catch (e) {
    console.warn("antispam: report failed", e);
    if (!quiet) await notify("Antyspam — błąd", "Nie udało się wysłać zgłoszenia: " + e.message);
    return null;
  }
}

/** Report as spam from the button / menu and handle the message locally. */
async function reportSpamAndFile(message) {
  await report(message, "spam");
  const s = await settings();
  await setJunk(message, true);
  if (s.moveOnReport) await moveToJunk(message);
}

async function reportHam(message) {
  const res = await report(message, "ham");
  if (res) await setJunk(message, false);
}

/** Logged in only: ask antispam to score a message and act on the decision. */
async function check(message, { manual = false } = {}) {
  const s = await settings();
  if (!s.token) {
    if (manual) await notify("Antyspam", "Sprawdzanie wiadomości wymaga zalogowania we wtyczce.");
    return null;
  }
  let res;
  try {
    res = await api("/api/plugin/check", { method: "POST", body: { raw_base64: await rawBase64(message.id) } });
  } catch (e) {
    console.warn("antispam: check failed", e);
    if (manual) await notify("Antyspam — błąd", "Sprawdzenie nie powiodło się: " + e.message);
    return null;
  }

  const action = res.decision === "spam" ? s.spamAction
    : res.decision === "quarantine" ? s.quarantineAction : "none";
  if (action === "mark" || action === "move") await setJunk(message, true);
  if (action === "move") await moveToJunk(message);

  if (manual || res.decision === "spam") {
    const labels = { spam: "SPAM", quarantine: "podejrzana", ham: "czysta", whitelisted: "biała lista" };
    await notify("Antyspam: " + (labels[res.decision] || res.decision),
      (message.subject || "(bez tematu)") + " — wynik " + res.score + "/" + res.spam_threshold);
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
  "antispam-ham": "To nie spam (Antyspam)",
  "antispam-check": "Sprawdź w Antyspamie",
};
for (const [id, title] of Object.entries(MENU)) {
  messenger.menus.create({ id, title, contexts: ["message_list"], icons: { "32": "icons/icon.svg" } });
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
