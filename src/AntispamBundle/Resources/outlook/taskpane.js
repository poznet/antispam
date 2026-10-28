/*
 * Antispam Pancernapanda - Outlook add-in task pane.
 *
 * The task pane is hosted by the antispam instance itself
 * (/plugin/outlook/taskpane.html), so calls to /api/plugin/* are same-origin.
 *
 * Not logged in: "Zgłoś spam" sends the message to the shared spam DB.
 * Logged in (mailbox e-mail + plugin/IMAP password): reports also teach the
 * account's rules, "To nie spam" and "Sprawdź" work, and - while the pane is
 * pinned - every opened message can be checked automatically.
 *
 * Office add-ins cannot move messages to Junk in read mode without Microsoft
 * Graph (Azure app registration + SSO), so the decision is only shown; the
 * user files the message with Outlook's own Junk / Report button.
 *
 * Server API: docs/thunderbird.md (/api/plugin/*), add-in: docs/outlook.md.
 */
"use strict";

// API base: the pane lives at <base>/plugin/outlook/taskpane.html.
const API = new URL("../../api/plugin/", window.location.href).href.replace(/\/+$/, "");
// Same upload cap as the Thunderbird plugin: headers + text body are enough.
const MAX_UPLOAD_BYTES = 1024 * 1024;
const MAX_UPLOAD_B64 = Math.floor(MAX_UPLOAD_BYTES / 3) * 4;

const state = { token: "", email: "", autoCheck: false, status: null, busy: false };
const $ = (id) => document.getElementById(id);

// --- settings (roaming with the mailbox; localStorage as a fallback) --------

function loadSettings() {
  const rs = Office.context.roamingSettings;
  for (const key of ["token", "email", "autoCheck"]) {
    let v = rs ? rs.get("antispam_" + key) : undefined;
    if (v === undefined || v === null) {
      try { v = JSON.parse(localStorage.getItem("antispam_" + key)); } catch (e) { v = undefined; }
    }
    if (v !== undefined && v !== null) state[key] = v;
  }
}

function saveSettings() {
  const rs = Office.context.roamingSettings;
  for (const key of ["token", "email", "autoCheck"]) {
    try { localStorage.setItem("antispam_" + key, JSON.stringify(state[key])); } catch (e) { /* blocked storage */ }
    if (rs) rs.set("antispam_" + key, state[key]);
  }
  if (rs) rs.saveAsync(() => {});
}

// --- API --------------------------------------------------------------------

async function api(path, { method = "GET", body = null, auth = true } = {}) {
  const headers = { "Accept": "application/json" };
  if (body !== null) headers["Content-Type"] = "application/json";
  if (auth && state.token) headers["Authorization"] = "Bearer " + state.token;

  const res = await fetch(API + path, {
    method,
    headers,
    body: body === null ? null : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (res.status === 401 && auth && state.token && path !== "/login") {
    // Token expired or account removed - fall back to anonymous mode.
    state.token = "";
    state.email = "";
    saveSettings();
    render();
  }
  if (!res.ok) {
    const err = new Error(data.error || ("HTTP " + res.status));
    err.status = res.status;
    throw err;
  }
  return data;
}

// --- message source ---------------------------------------------------------

function officeCall(fn) {
  return new Promise((resolve, reject) => {
    fn((r) => r.status === Office.AsyncResultStatus.Succeeded ? resolve(r.value) : reject(r.error || new Error("Office API error")));
  });
}

function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function supports(version) {
  return Office.context.requirements.isSetSupported("Mailbox", version);
}

/**
 * Raw RFC 822 source as base64, truncated to MAX_UPLOAD_BYTES.
 *
 * Mailbox 1.14 (new Outlook, web, Microsoft 365 desktop, Mac) gives the real
 * .eml. Older clients: internet headers (1.8) + text body, re-labelled as
 * text/plain so the server parser reads the body correctly.
 */
async function rawBase64() {
  const item = Office.context.mailbox.item;
  if (!item) throw new Error("Nie wybrano wiadomości.");

  if (supports("1.14") && typeof item.getAsFileAsync === "function") {
    try {
      const b64 = await officeCall((cb) => item.getAsFileAsync(cb));
      if (b64) return b64.length > MAX_UPLOAD_B64 ? b64.slice(0, MAX_UPLOAD_B64) : b64;
    } catch (e) { /* fall through */ }
  }

  let headerBlock = "";
  if (supports("1.8") && typeof item.getAllInternetHeadersAsync === "function") {
    try { headerBlock = await officeCall((cb) => item.getAllInternetHeadersAsync(cb)); } catch (e) { headerBlock = ""; }
  }
  const lines = [];
  if (headerBlock) {
    // Drop MIME structure headers (with their folded continuation lines).
    let skip = false;
    for (const line of headerBlock.split(/\r?\n/)) {
      if (line === "") continue;
      if (/^[ \t]/.test(line)) { if (!skip) lines.push(line); continue; }
      skip = /^(content-type|content-transfer-encoding|mime-version)\s*:/i.test(line);
      if (!skip) lines.push(line);
    }
  } else {
    const from = item.from || item.sender || {};
    lines.push("From: " + (from.displayName ? '"' + from.displayName.replace(/"/g, "") + '" ' : "") + "<" + (from.emailAddress || "") + ">");
    lines.push("Subject: " + (item.subject || ""));
    if (item.dateTimeCreated) lines.push("Date: " + item.dateTimeCreated.toUTCString());
    if (item.internetMessageId) lines.push("Message-ID: " + item.internetMessageId);
  }
  lines.push("MIME-Version: 1.0", "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: 8bit");

  let body = "";
  try { body = await officeCall((cb) => item.body.getAsync(Office.CoercionType.Text, cb)); } catch (e) { body = ""; }
  const raw = lines.join("\r\n") + "\r\n\r\n" + (body || "");
  const b64 = utf8ToBase64(raw.length > MAX_UPLOAD_BYTES ? raw.slice(0, MAX_UPLOAD_BYTES) : raw);
  return b64.length > MAX_UPLOAD_B64 ? b64.slice(0, MAX_UPLOAD_B64) : b64;
}

// --- UI ---------------------------------------------------------------------

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function showResult(kind, html) {
  const box = $("as-result");
  box.className = "as-result " + kind;
  box.innerHTML = html;
  box.hidden = false;
}

/** Short banner on the message itself (visible after the pane is closed). */
function notifyItem(text) {
  const item = Office.context.mailbox.item;
  if (!item || !item.notificationMessages) return;
  try {
    item.notificationMessages.replaceAsync("antispam", {
      type: Office.MailboxEnums.ItemNotificationMessageType.InformationalMessage,
      message: text.slice(0, 150),
      icon: "Icon16",
      persistent: false,
    });
  } catch (e) { /* not supported in this client */ }
}

function renderItem() {
  const item = Office.context.mailbox.item;
  const from = item ? (item.from || item.sender) : null;
  $("as-msg-from").textContent = from ? ((from.displayName ? from.displayName + " " : "") + "<" + from.emailAddress + ">") : "Nie wybrano wiadomości";
  $("as-msg-subject").textContent = item ? (item.subject || "(bez tematu)") : "";
}

function render() {
  const logged = !!state.token;
  const st = state.status || {};
  const enabled = st.enabled !== false;
  $("as-login-box").hidden = logged;
  $("as-user-box").hidden = !logged;
  $("as-user-email").textContent = state.email || "";
  $("as-autocheck").checked = !!state.autoCheck;

  const hasItem = !!Office.context.mailbox.item;
  $("as-spam").disabled = state.busy || !hasItem || !enabled || (!logged && st.anonymous_reports === false);
  $("as-ham").disabled = state.busy || !hasItem || !enabled || !logged;
  $("as-check").disabled = state.busy || !hasItem || !enabled || !logged || st.check_enabled === false;
  $("as-ham").title = logged ? "" : "Wymaga zalogowania";
  $("as-check").title = !logged ? "Wymaga zalogowania" : (st.check_enabled === false ? "Sprawdzanie wyłączone na serwerze" : "");
}

async function refreshStatus() {
  const origin = new URL(API).origin;
  try {
    state.status = await api("/status");
    if (state.token && !state.status.authenticated) {
      state.token = "";
      state.email = "";
      saveSettings();
    }
    $("as-server").textContent = state.status.enabled === false ? origin + " – wtyczka wyłączona" : origin;
  } catch (e) {
    state.status = null;
    $("as-server").textContent = "Brak połączenia z " + origin;
  }
  render();
}

async function run(fn) {
  if (state.busy) return;
  state.busy = true;
  render();
  try {
    await fn();
  } catch (e) {
    showResult("err", "<strong>Błąd:</strong> " + escapeHtml(e.message || e));
  } finally {
    state.busy = false;
    render();
  }
}

// --- actions ----------------------------------------------------------------

async function report(verdict) {
  showResult("", "Wysyłanie zgłoszenia…");
  const res = await api("/report", { method: "POST", body: { verdict, raw_base64: await rawBase64() } });
  const who = res.sender || "";
  const learned = res.rules && res.rules.length;
  const text = verdict === "spam"
    ? "Zgłoszono spam: " + who + (learned ? " (nadawca zablokowany)" : "")
    : "Oznaczono jako nie-spam: " + who + (learned ? " (nadawca na białej liście)" : "");
  showResult("ok", escapeHtml(text));
  $("as-junk-hint").hidden = verdict !== "spam";
  notifyItem("Antyspam: " + text);
}

const LABELS = { spam: "SPAM", quarantine: "podejrzana", ham: "czysta", whitelisted: "biała lista" };

async function check({ auto = false } = {}) {
  if (!auto) showResult("", "Sprawdzanie…");
  const res = await api("/check", { method: "POST", body: { raw_base64: await rawBase64() } });
  const label = LABELS[res.decision] || res.decision;
  const kind = res.decision === "spam" ? "err" : res.decision === "quarantine" ? "warn" : "ok";
  const reasons = (res.reasons || [])
    .filter((r) => r && r.score)
    .map((r) => "<li>" + escapeHtml(r.rule) + " (" + (r.score > 0 ? "+" : "") + r.score + ")</li>")
    .join("");
  showResult(kind, "<strong>Wynik: " + escapeHtml(label) + "</strong> – " + res.score + " / " + res.spam_threshold
    + (reasons ? "<ul>" + reasons + "</ul>" : ""));
  $("as-junk-hint").hidden = res.decision !== "spam";
  if (res.decision === "spam" || res.decision === "quarantine") {
    notifyItem("Antyspam: " + label + " (" + res.score + "/" + res.spam_threshold + ")");
  }
}

async function login(ev) {
  ev.preventDefault();
  const email = $("as-email").value.trim();
  const password = $("as-password").value;
  await run(async () => {
    const res = await api("/login", { method: "POST", body: { email, password }, auth: false });
    state.token = res.token;
    state.email = res.email;
    saveSettings();
    $("as-password").value = "";
    showResult("ok", "Zalogowano jako " + escapeHtml(res.email) + ".");
    await refreshStatus();
  });
}

function logout() {
  state.token = "";
  state.email = "";
  saveSettings();
  $("as-result").hidden = true;
  render();
}

function onItemChanged() {
  $("as-result").hidden = true;
  $("as-junk-hint").hidden = true;
  renderItem();
  render();
  if (state.autoCheck && state.token && Office.context.mailbox.item && (!state.status || state.status.check_enabled !== false)) {
    run(() => check({ auto: true }));
  }
}

Office.onReady((info) => {
  if (info.host !== Office.HostType.Outlook) return;
  if (!window.fetch || !window.TextEncoder) {
    showResult("err", "Ta wersja Outlooka używa przestarzałej przeglądarki (Internet Explorer). Użyj Outlooka z Microsoft 365, nowego Outlooka lub Outlooka w przeglądarce.");
    return;
  }
  loadSettings();
  $("as-spam").addEventListener("click", () => run(() => report("spam")));
  $("as-ham").addEventListener("click", () => run(() => report("ham")));
  $("as-check").addEventListener("click", () => run(() => check()));
  $("as-login").addEventListener("submit", login);
  $("as-logout").addEventListener("click", logout);
  $("as-autocheck").addEventListener("change", (e) => { state.autoCheck = e.target.checked; saveSettings(); });

  // Pinned pane: follow the selected message (Mailbox 1.5).
  if (supports("1.5")) {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, onItemChanged);
  }
  renderItem();
  render();
  refreshStatus().then(() => {
    if (state.autoCheck && state.token && Office.context.mailbox.item && state.status && state.status.check_enabled !== false) {
      run(() => check({ auto: true }));
    }
  });
});
