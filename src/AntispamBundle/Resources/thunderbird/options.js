"use strict";

const $ = id => document.getElementById(id);
const FLAGS = ["reportOnJunk", "moveOnReport", "autoCheck", "notify"];
const SELECTS = ["spamAction", "quarantineAction", "foreignMode"];

const ext = globalThis.messenger || globalThis.browser;
const send = msg => ext.runtime.sendMessage(msg);

const FOREIGN_HINTS = {
  report_only: "Spam i phishing z kont, które nie są zalogowane we wtyczce, trafiają tylko do administratora (wspólna baza spamu, zgłoszenia phishingu) - antyspam nie tworzy z nich reguł dla żadnej skrzynki. Do uwierzytelnienia używane jest logowanie innego konta. „To nie spam” i sprawdzanie są na takich kontach niedostępne.",
  linked: "Wiadomości z kont bez logowania są traktowane jak wiadomości domyślnej zalogowanej skrzynki: uczą jej reguł (czarna / biała lista), także „To nie spam”. Używaj tylko, jeśli te konta to aliasy tej samej skrzynki.",
  off: "Na kontach bez logowania wtyczka nic nie wysyła do antyspamu - przyciski tylko oznaczają wiadomość lokalnie (śmieci / nie-śmieci).",
};

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

/** Small DOM helper: el("div", {className: "x"}, child, "text"...). */
function el(tag, props, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "on") for (const [t, f] of Object.entries(v)) e.addEventListener(t, f);
    else e[k] = v;
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

function renderForeignHint() {
  $("foreignHint").textContent = FOREIGN_HINTS[$("foreignMode").value] || "";
}
$("foreignMode").addEventListener("change", renderForeignHint);

function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "" : d.toLocaleDateString("pl-PL");
}

/** One row per Thunderbird account: login state, login form or logout / test buttons. */
function renderAccounts(state) {
  const box = $("accounts");
  box.textContent = "";
  const rows = (state && state.accounts) || [];
  if (!rows.length) {
    box.appendChild(el("p", { className: "muted" }, "Nie znaleziono kont pocztowych w Thunderbirdzie."));
    return;
  }
  const def = state.defaultLogin;
  for (const a of rows) {
    const head = el("div", { className: "account-head" },
      el("strong", {}, a.name),
      a.emails.length ? el("span", { className: "muted" }, " " + a.emails.join(", ")) : null);
    const row = el("div", { className: "account" + (a.login ? " logged" : "") }, head);
    if (a.login) {
      const until = formatDate(a.login.expires_at);
      row.appendChild(el("p", { className: "account-state" },
        "Zalogowano jako ", el("strong", {}, a.login.email),
        until ? el("span", { className: "muted" }, " (ważne do " + until + ")") : null,
        def && def.key === a.id ? el("span", { className: "badge" }, "domyślne dla kont bez logowania") : null));
      if (a.emails.length && !a.emails.includes(String(a.login.email).toLowerCase())) {
        row.appendChild(el("p", { className: "muted" }, "Uwaga: to inny adres niż adres konta."));
      }
      row.appendChild(el("div", { className: "buttons" },
        el("button", { type: "button", className: "secondary", on: { click: () => runTest(a.id) } }, "Testuj"),
        el("button", { type: "button", className: "secondary", on: { click: () => logout(a.id) } }, "Wyloguj")));
    } else if (!a.general && !a.orphan) {
      const email = el("input", { type: "email", required: true, autocomplete: "username", value: a.emails[0] || "", placeholder: "adres skrzynki w antyspamie" });
      const password = el("input", { type: "password", required: true, autocomplete: "current-password", placeholder: "hasło wtyczki lub IMAP" });
      const form = el("form", { className: "login-inline", on: { submit: ev => { ev.preventDefault(); login(a.id, email, password); } } },
        email, password, el("button", { type: "submit" }, "Zaloguj"));
      row.appendChild(el("p", { className: "account-state muted" }, "Niezalogowano - " + ({
        report_only: "zgłoszenia tylko do administratora",
        linked: def ? "traktowane jak skrzynka " + def.email : "zgłoszenia anonimowe",
        off: "antyspam wyłączony dla tego konta",
      }[state.foreignMode] || "")));
      row.appendChild(form);
    }
    box.appendChild(row);
  }
}

async function loadAccounts() {
  try {
    const state = await send({ cmd: "accounts" });
    renderAccounts(state);
    return state;
  } catch (e) {
    $("accounts").textContent = "";
    $("accounts").appendChild(el("p", { className: "msg err" }, "Nie udało się wczytać kont: " + errorText(e)));
    return null;
  }
}

async function login(accountId, emailEl, passwordEl) {
  try {
    const res = await send({ cmd: "login", accountId, email: emailEl.value.trim(), password: passwordEl.value });
    passwordEl.value = "";
    show($("loginMsg"), "Zalogowano jako " + res.email, true);
  } catch (e) {
    show($("loginMsg"), "Logowanie nieudane: " + errorText(e), false);
  }
  await loadAccounts();
  loadEvents();
}

async function logout(accountId) {
  try {
    await send({ cmd: "logout", accountId });
    $("loginMsg").hidden = true;
  } catch (e) {
    show($("loginMsg"), "Wylogowanie nieudane: " + errorText(e), false);
  }
  await loadAccounts();
  loadEvents();
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
    renderForeignHint();
    $("server").value = s.server || "";
    setLoaded(true);
    renderSetup(s);
    const state = await loadAccounts();
    if (!s.server) {
      setState("Podaj adres serwera antyspamu (sekcja „Pierwsze uruchomienie” poniżej).", true);
      return;
    }

    try {
      const st = await send({ cmd: "status" });
      if (st && st.logged_out && st.logged_out.length) {
        // The background script dropped expired / unknown tokens.
        await loadAccounts();
        show($("loginMsg"), "Sesja wygasła lub konto nie istnieje (" + st.logged_out.join(", ") + ") — zaloguj się ponownie.", false);
      }
      const logged = ((state && state.accounts) || []).filter(a => a.login).length - ((st && st.logged_out) || []).length;
      const parts = ["Połączono z " + s.server];
      if (!st.enabled) parts.push("wtyczka wyłączona na serwerze");
      if (!st.anonymous_reports && logged <= 0) parts.push("zgłoszenia wymagają logowania");
      if (!st.check_enabled) parts.push("sprawdzanie poczty wyłączone na serwerze");
      if (s.foreignMode === "report_only" && st.report_only !== true) parts.push("serwer nie obsługuje zgłoszeń „tylko do administratora” - zaktualizuj antyspam");
      parts.push(logged > 0 ? "zalogowane konta: " + logged : "niezalogowano — działa tylko zgłaszanie spamu");
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

/**
 * First run without a server address (generic build): the "Pierwsze
 * uruchomienie" box on top asks for it; the bundled-address hint below the
 * server field is shown only for the instance build.
 */
function renderSetup(s) {
  $("setup").hidden = !!s.server;
  $("serverHint").textContent = s.bundledServer
    ? "Ustawiony automatycznie przy pobraniu wtyczki (" + s.bundledServer + "). Zmieniaj tylko, jeśli antyspam działa pod innym adresem."
    : "Adres podaje administrator antyspamu (strona „Konfiguracja wtyczki”: https://…/plugin/setup). Możesz wkleić cały link.";
}

/**
 * Save the server address. Must be called synchronously from a click handler:
 * permissions.request() is allowed only while handling user input.
 */
function saveServer(raw, extra, msgEl) {
  const server = normalizeServer(raw);
  if (raw.trim() && !server) {
    show(msgEl, "Nieprawidłowy adres - podaj np. https://antispam.example.pl", false);
    return;
  }
  const pattern = server ? originPattern(server) : null;
  const granted = pattern
    ? ext.permissions.request({ origins: [pattern] }).catch(() => false)
    : Promise.resolve(true);

  granted.then(async ok => {
    try {
      await ext.storage.local.set(Object.assign({ server }, extra));
      show(msgEl, ok ? "Zapisano" + (server ? " - " + server : "") : "Zapisano, ale bez zgody na połączenie z serwerem", ok);
    } catch (e) {
      show(msgEl, "Nie zapisano: " + errorText(e), false);
    }
    refresh();
  });
}

$("setupForm").addEventListener("submit", ev => {
  ev.preventDefault();
  saveServer($("setupServer").value, {}, $("setupMsg"));
});

$("save").addEventListener("click", () => {
  if (!loaded) return;
  const values = {};
  for (const f of FLAGS) values[f] = $(f).checked;
  for (const f of SELECTS) values[f] = $(f).value;
  saveServer($("server").value, values, $("saveMsg"));
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

/** Connection test for one account id, "*" or "all". */
async function runTest(accountId) {
  const list = $("testResult");
  list.hidden = false;
  list.textContent = "";
  list.appendChild(stepItem(true, "Testowanie…", ""));
  $("test").disabled = true;
  try {
    const res = await send({ cmd: "test", accountId });
    list.textContent = "";
    for (const st of (res && res.steps) || []) list.appendChild(stepItem(st.ok, st.name, st.text));
    if (!res || !res.steps) list.appendChild(stepItem(false, "Brak odpowiedzi skryptu wtyczki", "uruchom ponownie Thunderbirda"));
  } catch (e) {
    list.textContent = "";
    list.appendChild(stepItem(false, "Test nie wykonał się", errorText(e) + " — uruchom ponownie Thunderbirda"));
  } finally {
    $("test").disabled = false;
    loadAccounts();
    loadEvents();
  }
}

$("test").addEventListener("click", () => runTest("all"));

// --- event log -------------------------------------------------------------

let events = [];

function eventLine(ev) {
  return new Date(ev.t).toLocaleString("pl-PL") + " [" + (ev.kind || "") + "] " + (ev.ok ? "OK " : "BŁĄD ") + ev.text;
}

function eventsAsText() {
  const manifest = ext.runtime.getManifest ? ext.runtime.getManifest() : {};
  const head = "Antispam Pancernapanda - wtyczka Thunderbird " + (manifest.version || "") + ", dziennik zdarzeń z " + new Date().toLocaleString("pl-PL");
  return [head, ""].concat(events.map(ev => eventLine(ev) + (ev.detail ? "\n    " + ev.detail.split("\n").join("\n    ") : ""))).join("\n") + "\n";
}

async function loadEvents() {
  const list = $("events");
  list.textContent = "";
  try {
    events = (await send({ cmd: "events" })) || [];
  } catch (e) {
    events = [];
    list.appendChild(stepItem(false, "Nie udało się wczytać zdarzeń", errorText(e)));
    return;
  }
  if (!events.length) {
    list.appendChild(el("li", { className: "muted" }, "Brak zdarzeń."));
  }
  for (const ev of events) {
    const li = el("li", { className: ev.ok ? "ok" : "err" },
      el("span", { className: "ev-time" }, new Date(ev.t).toLocaleString("pl-PL")),
      el("span", { className: "ev-kind" }, ev.kind || ""),
      el("span", { className: "ev-text" }, ev.text));
    if (ev.detail) {
      li.appendChild(el("details", {}, el("summary", {}, "szczegóły"), el("pre", { className: "ev-detail" }, ev.detail)));
    }
    list.appendChild(li);
  }
}

async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) { /* fall back below */ }
  const ta = el("textarea", { value: text });
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  ta.remove();
  return ok;
}

$("eventsRefresh").addEventListener("click", loadEvents);
$("eventsCopy").addEventListener("click", async () => {
  await loadEvents();
  const ok = await copyText(eventsAsText());
  show($("eventsMsg"), ok ? "Skopiowano (" + events.length + " zdarzeń)" : "Nie udało się skopiować - użyj „Pobierz .txt”", ok);
});
$("eventsDownload").addEventListener("click", async () => {
  await loadEvents();
  const url = URL.createObjectURL(new Blob([eventsAsText()], { type: "text/plain;charset=utf-8" }));
  const a = el("a", { href: url, download: "antyspam-wtyczka-zdarzenia-" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".txt" });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
});
$("eventsClear").addEventListener("click", async () => {
  try { await send({ cmd: "clearEvents" }); } catch (e) { /* ignore */ }
  $("eventsMsg").hidden = true;
  loadEvents();
});

refresh();
loadEvents();
