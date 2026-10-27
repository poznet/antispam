"use strict";

const $ = id => document.getElementById(id);
const FLAGS = ["reportOnJunk", "moveOnReport", "autoCheck", "notify"];
const SELECTS = ["spamAction", "quarantineAction"];

const send = msg => messenger.runtime.sendMessage(msg);

function show(el, text, ok) {
  el.textContent = text;
  el.className = "msg " + (ok ? "ok" : "err");
  el.hidden = false;
}

function originPattern(url) {
  try {
    const u = new URL(url);
    return u.protocol + "//" + u.hostname + "/*";
  } catch (e) {
    return null;
  }
}

async function refresh() {
  const s = await send({ cmd: "settings" });
  for (const f of FLAGS) $(f).checked = !!s[f];
  for (const f of SELECTS) $(f).value = s[f];
  $("server").value = s.server || "";
  $("loggedIn").hidden = !s.token;
  $("loggedOut").hidden = !!s.token;
  $("who").textContent = s.email || "";

  try {
    const st = await send({ cmd: "status" });
    const parts = ["Połączono z " + s.server];
    if (!st.enabled) parts.push("wtyczka wyłączona na serwerze");
    if (!st.anonymous_reports && !st.authenticated) parts.push("zgłoszenia wymagają logowania");
    if (!st.check_enabled) parts.push("sprawdzanie poczty wyłączone na serwerze");
    if (!s.token) parts.push("niezalogowano — działa tylko zgłaszanie spamu");
    $("serverState").textContent = parts.join(" · ");
    if (s.token && !st.authenticated) await refresh(); // token expired → logged out by background
  } catch (e) {
    let text = "Brak połączenia z serwerem " + (s.server || "(nie ustawiono)") + ": " + e.message;
    if (/^http:\/\//i.test(s.server || "")) text += " — jeśli antyspam działa na https, zmień adres poniżej na https:// i zapisz.";
    $("serverState").textContent = text;
  }
}

$("loginForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const res = await send({ cmd: "login", email: $("email").value.trim(), password: $("password").value });
    $("password").value = "";
    show($("loginMsg"), "Zalogowano jako " + res.email, true);
  } catch (e) {
    show($("loginMsg"), "Logowanie nieudane: " + e.message, false);
  }
  refresh();
});

$("logout").addEventListener("click", async () => {
  await send({ cmd: "logout" });
  $("loginMsg").hidden = true;
  refresh();
});

$("save").addEventListener("click", () => {
  const server = $("server").value.trim().replace(/\/+$/, "");
  const pattern = server ? originPattern(server) : null;
  // permissions.request must run synchronously inside the click handler.
  const granted = pattern
    ? messenger.permissions.request({ origins: [pattern] }).catch(() => false)
    : Promise.resolve(true);

  granted.then(async ok => {
    const values = { server };
    for (const f of FLAGS) values[f] = $(f).checked;
    for (const f of SELECTS) values[f] = $(f).value;
    await messenger.storage.local.set(values);
    show($("saveMsg"), ok ? "Zapisano" : "Zapisano, ale bez zgody na połączenie z serwerem", ok);
    refresh();
  });
});

refresh();
