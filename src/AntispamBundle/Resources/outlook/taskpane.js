/*
 * Antispam Pancernapanda - Outlook add-in task pane.
 *
 * The task pane is hosted by the antispam instance itself
 * (/plugin/outlook/taskpane.html), so calls to /api/plugin/* are same-origin.
 *
 * Not logged in: "Zgłoś spam" sends the message to the shared spam DB.
 * Logged in (mailbox e-mail + plugin/IMAP password): reports also teach the
 * account's rules, "To nie spam" and "Sprawdź" work, and - while the pane is
 * pinned - every opened message can be checked automatically. "Zgłoś phishing"
 * (logged in) sends the whole .eml for the admin to inspect.
 *
 * "Zastosuj reguły antyspamu w folderze" (logged in): Office.js cannot read or
 * move a whole folder, so the server does it - the folder is picked from
 * GET /api/plugin/folders, POST /api/plugin/rescan {"folder"} queues the pass
 * (spam to SPAM, suspicious to QUARANTINE, nothing deleted) and the pane polls
 * GET /api/plugin/rescan?job=ID while it is open; the job id is kept in
 * localStorage, so a reopened pane goes on showing the progress.
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
// Same upload cap as the Thunderbird plugin: headers + text body are enough,
// and 700 KiB in base64 + JSON stays under a 1 MiB proxy body limit (nginx
// default). The server may lower it with max_upload_bytes in /status.
const MAX_UPLOAD_BYTES = 700 * 1024;
// Phishing reports keep the whole message up to the server's max_upload_bytes
// (at most PhishingReportService::MAX_RAW_BYTES); on a proxy 413 the first
// MAX_UPLOAD_BYTES are resent.
const MAX_PHISHING_BYTES = 10 * 1024 * 1024;
const b64Len = (bytes) => Math.floor(bytes / 3) * 4;

/** Decoded-bytes cap for spam reports / checks. */
function uploadLimit() {
  const max = state.status && Number(state.status.max_upload_bytes);
  return Number.isFinite(max) && max > 0 ? Math.min(MAX_UPLOAD_BYTES, max) : MAX_UPLOAD_BYTES;
}

/** Decoded-bytes cap for phishing reports. */
function phishingLimit() {
  const st = state.status || {};
  const pmax = Number(st.phishing_max_bytes) > 0 ? Number(st.phishing_max_bytes) : MAX_PHISHING_BYTES;
  const max = Number(st.max_upload_bytes);
  return Number.isFinite(max) && max > 0 ? Math.min(pmax, max) : pmax;
}

const state = { token: "", email: "", autoCheck: false, status: null, busy: false, folders: null, folderJob: null, folderBusy: false };
const FOLDER_POLL_MS = 10 * 1000;
let folderTimer = null;
const $ = (id) => document.getElementById(id);

// --- settings (roaming with the mailbox; non-secret ones also in localStorage) --

function loadSettings() {
  const rs = Office.context.roamingSettings;
  for (const key of ["token", "email", "autoCheck"]) {
    let v = rs ? rs.get("antispam_" + key) : undefined;
    if ((v === undefined || v === null) && key !== "token") {
      try { v = JSON.parse(localStorage.getItem("antispam_" + key)); } catch (e) { v = undefined; }
    }
    if (v !== undefined && v !== null) state[key] = v;
  }
}

function saveSettings() {
  const rs = Office.context.roamingSettings;
  try { localStorage.removeItem("antispam_token"); } catch (e) { /* blocked storage */ }
  for (const key of ["token", "email", "autoCheck"]) {
    // The bearer token stays in roaming settings only: localStorage is shared with the whole panel origin.
    if (key !== "token") try { localStorage.setItem("antispam_" + key, JSON.stringify(state[key])); } catch (e) { /* blocked storage */ }
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
    const err = new Error(data.message || data.error || ("HTTP " + res.status));
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
  return (await rawSource(b64Len(uploadLimit()))).base64;
}

/**
 * Like rawBase64, with a custom cap. `truncated` is true when the source was
 * cut, or when only headers + text body could be rebuilt (old clients).
 */
async function rawSource(maxB64) {
  const item = Office.context.mailbox.item;
  if (!item) throw new Error("Nie wybrano wiadomości.");

  if (supports("1.14") && typeof item.getAsFileAsync === "function") {
    try {
      const b64 = await officeCall((cb) => item.getAsFileAsync(cb));
      // Cut on a 4-char boundary so the server can still decode it.
      if (b64) return b64.length > maxB64 ? { base64: b64.slice(0, maxB64), truncated: true } : { base64: b64, truncated: false };
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
  return { base64: b64.length > maxB64 ? b64.slice(0, maxB64) : b64, truncated: true };
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
  $("as-phishing").disabled = state.busy || !hasItem || !enabled || !logged || st.phishing_reports !== true;
  $("as-phishing").title = !logged ? "Wymaga zalogowania" : (st.phishing_reports !== true ? "Serwer nie obsługuje zgłoszeń phishingu" : "");
  $("as-ham").title = logged ? "" : "Wymaga zalogowania";
  $("as-check").title = !logged ? "Wymaga zalogowania" : (st.check_enabled === false ? "Sprawdzanie wyłączone na serwerze" : "");

  const folderOk = logged && enabled && st.folder_rescan === true;
  $("as-folder-box").hidden = !folderOk;
  $("as-folder-run").disabled = !folderOk || state.folderBusy || !!state.folderJob || !$("as-folder").value;
  $("as-folder-run").textContent = state.folderJob ? "Trwa sprawdzanie folderu…" : "Zastosuj reguły w tym folderze";
}

// --- "Zastosuj reguły antyspamu w folderze" (server side) --------------------

function folderJobKey() {
  return "antispam_folderJob_" + (state.email || "");
}

function setFolderState(kind, text) {
  const el = $("as-folder-state");
  el.className = "as-folder-state as-muted" + (kind ? " " + kind : "");
  el.textContent = text;
  el.hidden = !text;
}

function folderCounters(r) {
  if (!r) return "";
  const parts = ["sprawdzono " + (r.checked ?? r.total ?? 0)];
  if (r.blacklisted) parts.push("czarna lista: " + r.blacklisted);
  if (r.moved_to_spam) parts.push("do SPAM: " + r.moved_to_spam);
  if (r.quarantined) parts.push("do kwarantanny: " + r.quarantined);
  if (r.whitelisted) parts.push("biała lista: " + r.whitelisted);
  if (r.move_failed) parts.push("nie udało się przenieść: " + r.move_failed);
  return parts.join(", ");
}

function jobProgress(job) {
  if (!job) return "";
  if (job.total) return job.done + " z " + job.total + " (" + Math.floor(100 * job.done / Math.max(1, job.total)) + "%)";
  return job.progress || (job.status === "queued" ? "w kolejce na serwerze" : "w toku");
}

async function loadFolders() {
  if (!state.token || !state.status || state.status.folder_rescan !== true) return;
  const sel = $("as-folder");
  const previous = sel.value || localStorage.getItem("antispam_folder") || "INBOX";
  sel.innerHTML = '<option value="">Wczytywanie folderów…</option>';
  sel.disabled = true;
  try {
    const res = await api("/folders");
    state.folders = res.folders || [];
    sel.innerHTML = "";
    for (const f of state.folders) {
      const o = document.createElement("option");
      o.value = f.name;
      o.textContent = (f.name === "INBOX" ? "Odebrane (INBOX)" : f.name) + (typeof f.messages === "number" ? " – " + f.messages : "");
      sel.appendChild(o);
    }
    if (state.folders.some((f) => f.name === previous)) sel.value = previous;
    if (!state.folders.length) sel.innerHTML = '<option value="">Brak folderów do sprawdzenia</option>';
  } catch (e) {
    state.folders = null;
    sel.innerHTML = '<option value="">Nie udało się wczytać folderów</option>';
    setFolderState("err", "Lista folderów: " + (e.message || e));
  } finally {
    sel.disabled = false;
    render();
  }
}

async function startFolderPass() {
  const folder = $("as-folder").value;
  if (!folder || state.folderJob) return;
  const label = folder === "INBOX" ? "Odebrane" : folder;
  state.folderBusy = true;
  render();
  setFolderState("", "Zlecanie sprawdzenia folderu " + label + "…");
  try {
    try { localStorage.setItem("antispam_folder", folder); } catch (e) { /* blocked storage */ }
    // INBOX: the regular full rescan (same counters), other folders: a folder pass.
    const res = await api("/rescan", { method: "POST", body: folder === "INBOX" ? {} : { folder } });
    if (res.active && res.job) {
      watchFolderJob(res.job.id, label);
      setFolderState("", (res.created ? "Zlecono sprawdzenie folderu " : "Sprawdzanie folderu już trwa: ") + label + " – " + jobProgress(res.job)
        + ". Serwer robi to w tle, możesz zamknąć panel.");
    } else {
      setFolderState("ok", "Folder " + label + " sprawdzony.");
    }
  } catch (e) {
    setFolderState("err", e.message || String(e));
  } finally {
    state.folderBusy = false;
    render();
  }
}

function watchFolderJob(id, label) {
  state.folderJob = { id, label };
  try { localStorage.setItem(folderJobKey(), JSON.stringify(state.folderJob)); } catch (e) { /* blocked storage */ }
  clearTimeout(folderTimer);
  folderTimer = setTimeout(pollFolderJob, FOLDER_POLL_MS);
  render();
}

function stopFolderWatch() {
  state.folderJob = null;
  clearTimeout(folderTimer);
  try { localStorage.removeItem(folderJobKey()); } catch (e) { /* blocked storage */ }
  render();
}

async function pollFolderJob() {
  const job = state.folderJob;
  if (!job || !state.token) return;
  let res;
  try {
    res = await api("/rescan?job=" + encodeURIComponent(job.id));
  } catch (e) {
    setFolderState("err", "Folder " + job.label + ": nie udało się odczytać postępu (" + (e.message || e) + "), ponawiam…");
    folderTimer = setTimeout(pollFolderJob, FOLDER_POLL_MS * 3);
    return;
  }
  if (res.active && res.job && res.job.id === job.id) {
    setFolderState("", "Folder " + job.label + ": " + jobProgress(res.job));
    folderTimer = setTimeout(pollFolderJob, FOLDER_POLL_MS);
    return;
  }
  stopFolderWatch();
  const f = res.finished;
  if (f && f.ok) {
    const text = "Zakończono sprawdzanie folderu " + job.label + ": " + folderCounters(f) + ".";
    setFolderState("ok", text);
    notifyItem("Antyspam: " + text);
  } else if (f) {
    setFolderState("err", "Sprawdzanie folderu " + job.label + " " + (f.status === "cancelled" ? "anulowano" : "nie powiodło się") + (f.error ? ": " + f.error : "") + ".");
  } else {
    setFolderState("", "Sprawdzanie folderu " + job.label + " zakończone - wynik w panelu antyspamu (Zadania w tle).");
  }
}

function resumeFolderWatch() {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(folderJobKey())); } catch (e) { saved = null; }
  if (saved && saved.id) {
    state.folderJob = saved;
    setFolderState("", "Folder " + saved.label + ": sprawdzanie postępu…");
    pollFolderJob();
  }
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

async function reportPhishing() {
  showResult("", "Wysyłanie zgłoszenia phishingu…");
  const src = await rawSource(b64Len(phishingLimit()));
  const fallback = b64Len(Math.min(MAX_UPLOAD_BYTES, phishingLimit()));
  let res;
  try {
    res = await api("/phishing", { method: "POST", body: { raw_base64: src.base64, truncated: src.truncated, client: "outlook" } });
  } catch (e) {
    if (e.status !== 413 || src.base64.length <= fallback) throw e;
    // A proxy in front of antispam limits the body size: send the head of the message.
    res = await api("/phishing", { method: "POST", body: { raw_base64: src.base64.slice(0, fallback), truncated: true, client: "outlook" } });
  }
  const text = "Zgłoszono próbę wyłudzenia: " + (res.sender || "")
    + (res.duplicate ? " (już była zgłoszona)" : "") + (res.rules && res.rules.length ? " – nadawca zablokowany" : "");
  showResult("ok", escapeHtml(text));
  $("as-junk-hint").hidden = false;
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
    loadFolders();
    resumeFolderWatch();
  });
}

function logout() {
  stopFolderWatch();
  setFolderState("", "");
  state.folders = null;
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
  $("as-phishing").addEventListener("click", () => run(() => reportPhishing()));
  $("as-login").addEventListener("submit", login);
  $("as-logout").addEventListener("click", logout);
  $("as-autocheck").addEventListener("change", (e) => { state.autoCheck = e.target.checked; saveSettings(); });
  $("as-folder").addEventListener("change", render);
  $("as-folder-reload").addEventListener("click", () => loadFolders());
  $("as-folder-run").addEventListener("click", () => startFolderPass());

  // Pinned pane: follow the selected message (Mailbox 1.5).
  if (supports("1.5")) {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, onItemChanged);
  }
  renderItem();
  render();
  refreshStatus().then(() => {
    loadFolders();
    resumeFolderWatch();
    if (state.autoCheck && state.token && Office.context.mailbox.item && state.status && state.status.check_enabled !== false) {
      run(() => check({ auto: true }));
    }
  });
});
