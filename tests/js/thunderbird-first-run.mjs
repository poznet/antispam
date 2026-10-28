// First-run flow of the Thunderbird plugin with mocked WebExtension APIs.
//   node tests/js/thunderbird-first-run.mjs
// Exit code 0 = all checks passed. Run by ThunderbirdFirstRunJsTest (PHPUnit,
// when node is installed) and by .github/workflows/thunderbird-plugin.yml.
import fs from "fs";
import path from "path";
import assert from "assert/strict";
import { fileURLToPath } from "url";

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src/AntispamBundle/Resources/thunderbird");
const read = f => fs.readFileSync(path.join(dir, f), "utf8");
const wait = ms => new Promise(r => setTimeout(r, ms));
let failures = 0;
async function check(name, fn) {
  try { await fn(); console.log("ok   " + name); } catch (e) { failures++; console.log("FAIL " + name + "\n     " + (e && e.message)); }
}

/** Fresh mocked environment; `bundled` = server in config.json (null = generic build, no file). */
function env(bundled, stored = {}) {
  const store = Object.assign({}, stored);
  const listeners = {};
  const calls = { optionsOpened: 0, permissionRequests: [], fetches: [] };
  const ev = n => ({ addListener: f => (listeners[n] = f) });
  const messenger = {
    runtime: {
      getURL: p => "ext://" + p,
      getManifest: () => JSON.parse(read("manifest.json")),
      getBrowserInfo: async () => ({ name: "Thunderbird", version: "153.6.0" }),
      openOptionsPage: async () => { calls.optionsOpened++; },
      onMessage: ev("onMessage"), onInstalled: ev("onInstalled"),
      sendMessage: async msg => listeners.onMessage(msg),
    },
    storage: { local: {
      get: async k => { const o = {}; for (const x of [].concat(k)) if (x in store) o[x] = store[x]; return o; },
      set: async o => { Object.assign(store, o); },
    } },
    permissions: {
      contains: async () => true,
      request: async p => { calls.permissionRequests.push(p.origins[0]); return true; },
    },
    notifications: { create: async () => {} },
    messageDisplayAction: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}, onClicked: ev("btn") },
    messageDisplay: { getDisplayedMessages: async () => [] },
    messages: { getRaw: async () => "From: a@b\r\n\r\nx", update: async () => {}, move: async () => {}, onNewMailReceived: ev("nm"), onUpdated: ev("upd"), onMoved: ev("mv"), continueList: async () => null },
    folders: { query: async () => [] },
    accounts: { get: async () => ({ identities: [] }) },
    menus: { create: () => {}, onClicked: ev("menu") },
  };
  const fetch = async (url) => {
    calls.fetches.push(url);
    if (url === "ext://config.json") {
      if (bundled === null) throw new TypeError("NetworkError when attempting to fetch resource.");
      return { json: async () => ({ server: bundled }) };
    }
    if (url.endsWith("/api/plugin/status")) return { ok: true, status: 200, json: async () => ({ enabled: true, anonymous_reports: true, check_enabled: true, authenticated: false }) };
    return { ok: true, status: 200, json: async () => ({}) };
  };
  return { store, listeners, calls, messenger, fetch };
}

/** Loads common.js + background.js into a function scope with the mocks. */
function loadBackground(e) {
  const src = read("common.js") + "\n" + read("background.js") + "\nreturn { normalizeServer, settings };";
  return new Function("messenger", "fetch", "browser", src)(e.messenger, e.fetch, e.messenger);
}

/** Minimal DOM for options.html: elements by id with value / hidden / listeners. */
function fakeDocument(html) {
  const els = {};
  for (const m of html.matchAll(/id="([^"]+)"/g)) {
    const id = m[1];
    const hidden = new RegExp('id="' + id + '"[^>]*\\shidden').test(html);
    els[id] = { id, value: "", checked: false, hidden, disabled: false, textContent: "", className: "", handlers: {},
      addEventListener(t, f) { this.handlers[t] = f; }, appendChild() {} };
  }
  return { getElementById: id => els[id], createElement: () => ({ appendChild() {}, set textContent(v) {} }), createTextNode: t => t, els };
}

function loadOptions(e) {
  const doc = fakeDocument(read("options.html"));
  const src = read("common.js") + "\n" + read("options.js");
  new Function("document", "globalThis", src)(doc, { messenger: e.messenger });
  return doc.els;
}

await check("normalizeServer accepts setup link, bare host, panel URL; rejects junk", async () => {
  const { normalizeServer } = loadBackground(env(null));
  assert.equal(normalizeServer("https://antispam.example.pl/plugin/setup"), "https://antispam.example.pl");
  assert.equal(normalizeServer(" antispam.example.pl/ "), "https://antispam.example.pl");
  assert.equal(normalizeServer("https://x.pl:8443/sub/panel?tab=1#a"), "https://x.pl:8443/sub");
  assert.equal(normalizeServer("https://x.pl/plugin/download?v=1.2.0"), "https://x.pl");
  assert.equal(normalizeServer("http://10.0.0.5/"), "http://10.0.0.5");
  assert.equal(normalizeServer("ftp://x.pl"), "");
  assert.equal(normalizeServer("https://user:pw@x.pl"), "");
  assert.equal(normalizeServer(""), "");
});

await check("generic build: no server, install opens the settings page", async () => {
  const e = env(null);
  const bg = loadBackground(e);
  assert.equal((await bg.settings()).server, "");
  await e.listeners.onInstalled({ reason: "install" });
  assert.equal(e.calls.optionsOpened, 1);
  await e.listeners.onInstalled({ reason: "update" });
  assert.equal(e.calls.optionsOpened, 1, "an update does not reopen the settings");
});

await check("instance build: bundled server, install does not open settings", async () => {
  const e = env("https://antispam.example.pl/");
  const bg = loadBackground(e);
  const s = await bg.settings();
  assert.equal(s.server, "https://antispam.example.pl");
  assert.equal(s.bundledServer, "https://antispam.example.pl");
  await e.listeners.onInstalled({ reason: "install" });
  assert.equal(e.calls.optionsOpened, 0);
});

await check("stored server wins over the bundled one and is normalised", async () => {
  const e = env("https://old.example.pl", { server: "https://new.example.pl/plugin/setup" });
  assert.equal((await loadBackground(e).settings()).server, "https://new.example.pl");
});

await check("options page (generic): first-run box shown, pasted setup link saved with permission", async () => {
  const e = env(null);
  loadBackground(e);
  const el = loadOptions(e);
  await wait(20);
  assert.equal(el.setup.hidden, false, "first-run box visible");
  assert.match(el.serverState.textContent, /Podaj adres serwera/);
  assert.match(el.serverHint.textContent, /plugin\/setup/);

  el.setupServer.value = "https://antispam.example.pl/plugin/setup";
  el.setupForm.handlers.submit({ preventDefault() {} });
  await wait(30);
  assert.deepEqual(e.calls.permissionRequests, ["https://antispam.example.pl/*"]);
  assert.equal(e.store.server, "https://antispam.example.pl");
  assert.equal(el.setup.hidden, true, "first-run box hidden after saving");
  assert.match(el.serverState.textContent, /Połączono z https:\/\/antispam\.example\.pl/);
  assert.ok(e.calls.fetches.includes("https://antispam.example.pl/api/plugin/status"));
});

await check("options page: invalid address is refused, nothing stored", async () => {
  const e = env(null);
  loadBackground(e);
  const el = loadOptions(e);
  await wait(20);
  el.setupServer.value = "ftp://nope";
  el.setupForm.handlers.submit({ preventDefault() {} });
  await wait(20);
  assert.equal(e.store.server, undefined);
  assert.equal(e.calls.permissionRequests.length, 0);
  assert.match(el.setupMsg.textContent, /Nieprawidłowy adres/);
});

await check("options page (instance): no first-run box, Save keeps flags and server", async () => {
  const e = env("https://antispam.example.pl");
  loadBackground(e);
  const el = loadOptions(e);
  await wait(20);
  assert.equal(el.setup.hidden, true);
  assert.equal(el.server.value, "https://antispam.example.pl");
  assert.match(el.serverHint.textContent, /automatycznie/);
  el.notify.checked = false;
  el.save.handlers.click();
  await wait(20);
  assert.equal(e.store.server, "https://antispam.example.pl");
  assert.equal(e.store.notify, false);
});

if (failures) {
  console.log(failures + " check(s) failed");
  process.exit(1);
}
console.log("all checks passed");
