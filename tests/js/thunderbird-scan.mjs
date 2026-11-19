// "Sprawdź tę wiadomość" (plugin 1.7.0): POST /api/plugin/scan (antivirus
// first, then the rules), result window, local action, fallback to /check on
// older servers. Mocked WebExtension APIs.
//   node tests/js/thunderbird-scan.mjs
import fs from "fs";
import path from "path";
import assert from "assert/strict";
import { fileURLToPath } from "url";

const dir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../src/AntispamBundle/Resources/thunderbird");
const read = f => fs.readFileSync(path.join(dir, f), "utf8");
let failures = 0;
async function check(name, fn) {
  try { await fn(); console.log("ok   " + name); } catch (e) { failures++; console.log("FAIL " + name + "\n     " + (e && e.stack)); }
}
const quiet = { log() {}, warn() {}, error() {} };
const SERVER = "https://antispam.example.pl";

const SCAN = {
  decision: "spam", spam: true, score: 60, spam_threshold: 10, quarantine_threshold: 5, sender: "a@x.pl", subject: "Paczka",
  reasons: [{ rule: "clamav:Eicar-Test-Signature", score: 50 }],
  antivirus: { attachments: 1, infected: true, score: 50, reasons: [], truncated: false,
    clamav: { enabled: true, items: [{ name: "cała wiadomość", size: 900, status: "infected", signature: "Eicar" }] },
    virustotal: { enabled: true, items: [{ name: "faktura.exe", status: "malicious", malicious: 60, total: 70, link: "https://www.virustotal.com/gui/file/x" }] } },
};

function env({ scan = true, store = {} } = {}) {
  store = Object.assign({ server: SERVER, logins: { account1: { token: "T1", email: "jan@firma.pl" } }, spamAction: "mark" }, store);
  const listeners = {};
  const requests = [];
  const windows = [];
  const notes = [];
  const updates = [];
  const ev = n => ({ addListener: f => (listeners[n] = f) });
  const messenger = {
    runtime: { getURL: p => "ext://" + p, getManifest: () => JSON.parse(read("manifest.json")), getBrowserInfo: async () => ({ version: "153" }),
      openOptionsPage: async () => {}, onMessage: ev("onMessage"), onInstalled: ev("onInstalled") },
    storage: { local: {
      get: async k => { const o = {}; for (const x of [].concat(k)) if (x in store) o[x] = JSON.parse(JSON.stringify(store[x])); return o; },
      set: async o => { Object.assign(store, JSON.parse(JSON.stringify(o))); },
      remove: async k => { for (const x of [].concat(k)) delete store[x]; },
    } },
    permissions: { contains: async () => true, request: async () => true },
    notifications: { create: async (a, b) => { notes.push(typeof a === "object" ? a : b); } },
    windows: { create: async o => { windows.push(o); return { id: 9 }; } },
    messageDisplayAction: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}, onClicked: ev("btn") },
    messages: { getRaw: async () => "From: a@x.pl\r\nSubject: Paczka\r\n\r\nbody", get: async id => MSG, update: async (id, u) => { updates.push(u); }, move: async () => {},
      onNewMailReceived: ev("n"), onUpdated: ev("u"), onMoved: ev("m") },
    folders: { query: async () => [] },
    accounts: { list: async () => [{ id: "account1", name: "Jan", type: "imap", identities: [{ email: "jan@firma.pl" }] }], get: async () => null },
    menus: { create: () => {}, onClicked: ev("menu"), onShown: ev("menuShown"), update: async () => {}, refresh: async () => {} },
  };
  const fetch = async (url, opts = {}) => {
    if (url === "ext://config.json") throw new TypeError("no config.json");
    const p = url.replace(SERVER, "");
    requests.push({ path: p, method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null, auth: (opts.headers || {}).Authorization });
    const json = (d, status = 200) => ({ ok: status < 400, status, json: async () => d });
    if (p === "/api/plugin/status") return json({ enabled: true, authenticated: true, scan, antivirus: { clamav: true, virustotal: true }, phishing_max_bytes: 10485760, max_upload_bytes: 2097152 });
    if (p === "/api/plugin/scan") return json(SCAN);
    if (p === "/api/plugin/check") return json({ decision: "ham", score: 1, spam_threshold: 10, reasons: [] });
    return json({});
  };
  const src = read("common.js") + "\n" + read("background.js") + "\nreturn { scanMessage, scanAvSummary };";
  const bg = new Function("messenger", "fetch", "browser", "console", src)(messenger, fetch, messenger, quiet);
  return { bg, listeners, requests, windows, notes, updates, store };
}

const MSG = { id: 1, author: "a@x.pl", subject: "Paczka", folder: { accountId: "account1", path: "/INBOX" } };

await check("scan sends the whole message to /scan, opens the result window, applies the spam setting", async () => {
  const t = env();
  const res = await t.bg.scanMessage(MSG);
  assert.equal(res.decision, "spam");
  const scan = t.requests.find(r => r.path === "/api/plugin/scan");
  assert.ok(scan, "scan request");
  assert.equal(scan.auth, "Bearer T1");
  assert.ok(scan.body.raw_base64.length > 10);
  assert.equal(scan.body.truncated, false);
  assert.equal(t.windows.length, 1);
  assert.match(t.windows[0].url, /^scan-result\.html\?id=\d+$/);
  assert.deepEqual(t.updates, [{ junk: true }], "marked as junk (spamAction=mark)");
  assert.ok(t.notes.some(n => /WIRUS/.test(n.title)));
  const id = t.windows[0].url.split("=")[1];
  const entry = await t.listeners.onMessage({ cmd: "scanResult", id });
  assert.equal(entry.result.antivirus.infected, true);
  assert.equal(entry.action, "mark");
  assert.equal(await t.listeners.onMessage({ cmd: "scanResult", id: "999" }), null);
});

await check("older server without scan: falls back to /check", async () => {
  const t = env({ scan: false });
  await t.bg.scanMessage(MSG);
  assert.ok(t.requests.some(r => r.path === "/api/plugin/check"));
  assert.ok(!t.requests.some(r => r.path === "/api/plugin/scan"));
  assert.equal(t.windows.length, 0);
});

await check("antivirus summary", async () => {
  const t = env();
  assert.equal(t.bg.scanAvSummary(SCAN.antivirus), "ClamAV: 1 zainfekowane, VirusTotal: 1 złośliwe, załączniki: 1");
  assert.equal(t.bg.scanAvSummary({ attachments: 0, clamav: { enabled: false }, virustotal: { enabled: true, items: [] } }),
    "ClamAV: wyłączony na serwerze, VirusTotal: brak załączników, załączniki: 0");
});

await check("result window script parses", async () => {
  new Function(read("scan-result.js").replace(/^main\(\)[\s\S]*$/m, ""));
  assert.match(read("scan-result.html"), /scan-result\.js/);
});

if (failures) { console.log(failures + " failed"); process.exit(1); }
