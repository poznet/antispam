"use strict";

const $ = id => document.getElementById(id);
const FLAGS = ["reportOnJunk", "moveOnReport", "autoCheck", "notify"];
const SELECTS = ["spamAction", "quarantineAction"];

const ext = globalThis.messenger || globalThis.browser;
const send = msg => ext.runtime.sendMessage(msg);

// Saving writes every field from the form, so it is allowed only once the
// stored settings are on the page - otherwise it would overwrite them with
// the blank initial form.
let loaded = false;

function errorText(e) {
  return (e && e.message) || String(e);
}

function show(el, text, ok) {
  el.textContent = text;
  el.className = "msg " + (ok ? "ok" : "err");
  el.hidden = false;
}

function setState(text, isError) {
  const el = $("serverState");
  el.textContent = text;
  el.className = isError ? "state-err" : "muted";
}

function setLoaded(value) {
  loaded = value;
  $("save").disabled = !value;
}

function originPattern(url) {
  try {
    const u = new URL(url);
    return u.protocol + "//" + u.hostname + "/*";
  } catch (e) {
    return null;
  }
}

function renderAccount(s) {
  $("loggedIn").hidden = !s.token;
  $("loggedOut").hidden = !!s.token;
  $("who").textContent = s.email || "";
}

async function refresh() {
  try {
    let s;
    try {
      s = await send({ cmd: "settings" });
      if (!s || typeof s !== "object") throw new Error("brak odpowiedzi skryptu wtyczki");
    } catch (e) {
      setLoaded(false);
      setState("Nie udało się wczytać ustawień wtyczki: " + errorText(e).replace(/\.$/, "")
        + ". Zamknij tę kartę i otwórz ustawienia ponownie; jeśli to nie pomoże, uruchom ponownie Thunderbirda.", true);
      return;
    }

    for (const f of FLAGS) $(f).checked = !!s[f];
    for (const f of SELECTS) $(f).value = s[f];
    $("server").value = s.server || "";
    renderAccount(s);
    setLoaded(true);

    try {
      const st = await send({ cmd: "status" });
      if (st && st.logged_out) {
        // The background script dropped an expired / unknown token.
        s.token = "";
        s.email = "";
        renderAccount(s);
        show($("loginMsg"), "Sesja wygasła lub konto nie istnieje — zaloguj się ponownie.", false);
      }
      const parts = ["Połączono z " + s.server];
      if (!st.enabled) parts.push("wtyczka wyłączona na serwerze");
      if (!st.anonymous_reports && !st.authenticated) parts.push("zgłoszenia wymagają logowania");
      if (!st.check_enabled) parts.push("sprawdzanie poczty wyłączone na serwerze");
      if (!s.token) parts.push("niezalogowano — działa tylko zgłaszanie spamu");
      setState(parts.join(" · "), false);
    } catch (e) {
      let text = "Brak połączenia z serwerem " + (s.server || "(nie ustawiono)") + ": " + errorText(e);
      if (/^http:\/\//i.test(s.server || "")) text += " — jeśli antyspam działa na https, zmień adres poniżej na https:// i zapisz.";
      setState(text, true);
    }
  } catch (e) {
    console.error("antispam options:", e);
    setState("Błąd strony ustawień: " + errorText(e), true);
  }
}

$("loginForm").addEventListener("submit", async ev => {
  ev.preventDefault();
  try {
    const res = await send({ cmd: "login", email: $("email").value.trim(), password: $("password").value });
    $("password").value = "";
    show($("loginMsg"), "Zalogowano jako " + res.email, true);
  } catch (e) {
    show($("loginMsg"), "Logowanie nieudane: " + errorText(e), false);
  }
  refresh();
});

$("logout").addEventListener("click", async () => {
  try {
    await send({ cmd: "logout" });
    $("loginMsg").hidden = true;
  } catch (e) {
    show($("loginMsg"), "Wylogowanie nieudane: " + errorText(e), false);
  }
  refresh();
});

$("save").addEventListener("click", () => {
  if (!loaded) return;
  const server = $("server").value.trim().replace(/\/+$/, "");
  const pattern = server ? originPattern(server) : null;
  // permissions.request must run synchronously inside the click handler.
  const granted = pattern
    ? ext.permissions.request({ origins: [pattern] }).catch(() => false)
    : Promise.resolve(true);

  granted.then(async ok => {
    const values = { server };
    for (const f of FLAGS) values[f] = $(f).checked;
    for (const f of SELECTS) values[f] = $(f).value;
    try {
      await ext.storage.local.set(values);
      show($("saveMsg"), ok ? "Zapisano" : "Zapisano, ale bez zgody na połączenie z serwerem", ok);
    } catch (e) {
      show($("saveMsg"), "Nie zapisano: " + errorText(e), false);
    }
    refresh();
  });
});

function stepItem(ok, title, text) {
  const li = document.createElement("li");
  li.className = ok ? "ok" : "err";
  const b = document.createElement("strong");
  b.textContent = (ok ? "✓ " : "✗ ") + title;
  li.appendChild(b);
  if (text) li.appendChild(document.createTextNode(" — " + text));
  return li;
}

$("test").addEventListener("click", async () => {
  const list = $("testResult");
  list.hidden = false;
  list.textContent = "";
  list.appendChild(stepItem(true, "Testowanie…", ""));
  $("test").disabled = true;
  try {
    const res = await send({ cmd: "test" });
    list.textContent = "";
    for (const st of (res && res.steps) || []) list.appendChild(stepItem(st.ok, st.name, st.text));
    if (!res || !res.steps) list.appendChild(stepItem(false, "Brak odpowiedzi skryptu wtyczki", "uruchom ponownie Thunderbirda"));
  } catch (e) {
    list.textContent = "";
    list.appendChild(stepItem(false, "Test nie wykonał się", errorText(e) + " — uruchom ponownie Thunderbirda"));
  } finally {
    $("test").disabled = false;
    loadEvents();
  }
});

async function loadEvents() {
  const list = $("events");
  list.textContent = "";
  let events = [];
  try {
    events = (await send({ cmd: "events" })) || [];
  } catch (e) {
    list.appendChild(stepItem(false, "Nie udało się wczytać zdarzeń", errorText(e)));
    return;
  }
  if (!events.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "Brak zdarzeń.";
    list.appendChild(li);
  }
  for (const ev of events) {
    const d = new Date(ev.t);
    list.appendChild(stepItem(ev.ok, d.toLocaleString("pl-PL"), ev.text));
  }
}

$("eventsRefresh").addEventListener("click", loadEvents);
$("eventsClear").addEventListener("click", async () => {
  try { await send({ cmd: "clearEvents" }); } catch (e) { /* ignore */ }
  loadEvents();
});

refresh();
loadEvents();
