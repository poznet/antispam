// Complex rules in the Thunderbird plugin (1.6.0): local evaluation
// (complexEval / complexProvider / matchComplex, = ComplexRuleEngine) and
// the settings commands. Mocked WebExtension APIs.
//   node tests/js/thunderbird-complex-rules.mjs
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

function env(store = {}) {
  store = Object.assign({ server: SERVER, logins: { account1: { token: "T1", email: "jan@firma.pl" } } }, store);
  const listeners = {};
  const requests = [];
  const ev = n => ({ addListener: f => (listeners[n] = f) });
  const full = {
    headers: { "authentication-results": ["mx.firma.pl; spf=softfail; dkim=none; dmarc=fail"], "reply-to": ["Pay <pay@other.top>"], "x-mailer": ["PHPMailer 6.1"], "list-unsubscribe": ["<mailto:u@x>"] },
    contentType: "multipart/mixed",
    parts: [
      { contentType: "text/plain", body: "Prosimy o   zapłatę: https://pay.bad-link.top/x" },
      { contentType: "application/x-msdownload", name: "faktura.pdf.exe", body: "" },
    ],
  };
  const messenger = {
    runtime: { getURL: p => "ext://" + p, getManifest: () => JSON.parse(read("manifest.json")), getBrowserInfo: async () => ({ version: "153" }),
      openOptionsPage: async () => {}, onMessage: ev("onMessage"), onInstalled: ev("onInstalled") },
    storage: { local: {
      get: async k => { const o = {}; for (const x of [].concat(k)) if (x in store) o[x] = JSON.parse(JSON.stringify(store[x])); return o; },
      set: async o => { Object.assign(store, JSON.parse(JSON.stringify(o))); },
      remove: async k => { for (const x of [].concat(k)) delete store[x]; },
    } },
    permissions: { contains: async () => true, request: async () => true },
    notifications: { create: async () => {} },
    messageDisplayAction: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}, onClicked: ev("btn") },
    messages: { getFull: async () => full, getRaw: async () => "", update: async () => {}, move: async () => {}, onNewMailReceived: ev("n"), onUpdated: ev("u"), onMoved: ev("m") },
    folders: { query: async () => [] },
    accounts: { list: async () => [{ id: "account1", name: "Jan", type: "imap", identities: [{ email: "jan@firma.pl" }] }], get: async () => null },
    menus: { create: () => {}, onClicked: ev("menu"), onShown: ev("menuShown"), update: async () => {}, refresh: async () => {} },
  };
  const fetch = async (url, opts = {}) => {
    if (url === "ext://config.json") throw new TypeError("no config.json");
    const p = url.replace(SERVER, "");
    requests.push({ path: p, method: opts.method || "GET", body: opts.body ? JSON.parse(opts.body) : null, auth: (opts.headers || {}).Authorization });
    const json = d => ({ ok: true, status: 200, json: async () => d });
    if (p === "/api/plugin/complex-rules" && (opts.method || "GET") === "GET") return json({ mailbox: "jan@firma.pl", can_global: false, rules: [], actions: { spam: "Spam" } });
    if (p.startsWith("/api/plugin/complex-rules")) return json({ rule: { id: 3, name: "x", global: false, description: "d" } });
    return json({});
  };
  const src = read("common.js") + "\n" + read("background.js")
    + "\nreturn { complexEval, complexCompile, complexProvider, compileComplexRules, matchComplex };";
  const bg = new Function("messenger", "fetch", "browser", "console", src)(messenger, fetch, messenger, quiet);
  return { bg, listeners, requests, store };
}

const MSG = { id: 1, author: "\"Dział Faktur\" <Faktury@Mail.Evil.RU>", subject: "Pilna FAKTURA nr 12/2026", recipients: ["Jan <jan@firma.pl>"], ccList: ["biuro@firma.pl"], size: 900, folder: { accountId: "account1" } };
const C = (field, match, value, negate = false, extra = {}) => Object.assign({ field, match, value, negate }, extra);

await check("fields and AND / OR / NOT like the server", async () => {
  const { bg } = env();
  const v = bg.complexProvider(MSG, "jan@firma.pl", ["gmail.com"]);
  assert.deepEqual(await v("from"), ["faktury@mail.evil.ru"]);
  assert.deepEqual(await v("from_name"), ["Dział Faktur"]);
  assert.deepEqual(await v("to"), ["jan@firma.pl", "biuro@firma.pl"]);
  assert.deepEqual(await v("reply_to"), ["pay@other.top"]);
  assert.deepEqual(await v("attachment"), ["faktura.pdf.exe"]);
  assert.deepEqual(await v("attachment_count"), ["1"]);
  assert.deepEqual(await v("link_domain"), ["pay.bad-link.top"]);
  assert.deepEqual(await v("auth_dmarc"), ["fail"]);
  assert.deepEqual(await v("message_type"), ["list"]);
  assert.deepEqual(await v("from_scope"), ["external"]);
  assert.deepEqual(await v("from_freemail"), ["nie"]);
  assert.deepEqual(await v("size_kb"), ["1"]);
  const ev = async t => bg.complexEval(bg.complexCompile(t), bg.complexProvider(MSG, "jan@firma.pl", []));
  assert.equal(await ev({ op: "and", items: [C("subject", "contains", "faktura"), C("body", "contains", "umowa", true)] }), true);
  assert.equal(await ev({ op: "and", items: [C("subject", "contains", "faktura"), C("body", "contains", "o zapłatę", true)] }), false);
  assert.equal(await ev({ op: "or", negate: true, items: [C("from_domain", "wildcard", "*.ru"), C("attachment", "regex", "\\.exe$")] }), false);
  assert.equal(await ev({ op: "and", items: [C("subject", "wildcard", "pilna*nr ??/2026")] }), true);
  assert.equal(await ev({ op: "and", items: [C("header", "empty", undefined, false, { header: "List-Id" })] }), true);
  assert.equal(await ev({ op: "and", items: [C("attachment_count", "gt", "0")] }), true);
});

await check("rules needing DNS / WHOIS are left to the server; whitelist wins", async () => {
  const { bg } = env();
  const compiled = bg.compileComplexRules([
    { id: 1, name: "Nowe domeny", action: "spam", enabled: true, conditions: { op: "and", items: [C("domain_age", "lt", "30")] } },
    { id: 2, name: "Faktury", action: "quarantine", enabled: true, conditions: { op: "and", items: [C("subject", "contains", "faktura")] } },
    { id: 3, name: "Wyłączona", action: "spam", enabled: false, conditions: { op: "and", items: [C("subject", "contains", "pilna")] } },
    { id: 4, name: "Zły regex", action: "spam", enabled: true, conditions: { op: "and", items: [C("subject", "regex", "(?<=x")] } },
  ]);
  assert.deepEqual(compiled.serverOnly, ["Nowe domeny"]);
  assert.deepEqual(compiled.bad, ["Zły regex"]);
  assert.equal(compiled.local.length, 1);
  const hit = await bg.matchComplex(compiled, bg.complexProvider(MSG, "jan@firma.pl", []));
  assert.equal(hit.verdict, "black");
  assert.match(hit.rule, /#2 Faktury \(quarantine/);
  const white = bg.compileComplexRules([
    { id: 5, name: "Biuro", action: "whitelist", enabled: true, conditions: { op: "and", items: [C("to", "equals", "biuro@firma.pl")] } },
    { id: 2, name: "Faktury", action: "spam", enabled: true, conditions: { op: "and", items: [C("subject", "contains", "faktura")] } },
  ]);
  assert.equal((await bg.matchComplex(white, bg.complexProvider(MSG, "", []))).verdict, "white");
});

await check("settings commands: list, save (POST / PUT), delete, draft", async () => {
  const { listeners, requests, store } = env();
  const send = m => listeners.onMessage(m);
  const list = await send({ cmd: "complexRules", accountId: "account1" });
  assert.equal(list.mailbox, "jan@firma.pl");
  assert.equal(requests.at(-1).auth, "Bearer T1");
  await send({ cmd: "complexSave", accountId: "account1", rule: { name: "x", action: "spam", score: "7", conditions: { op: "and", items: [C("subject", "contains", "a")] } } });
  assert.equal(requests.at(-1).method, "POST");
  assert.equal(requests.at(-1).body.score, 7);
  await send({ cmd: "complexSave", accountId: "account1", rule: { id: 3, name: "x", action: "spam", global: true, conditions: {} } });
  assert.equal(requests.at(-1).method, "PUT");
  assert.equal(requests.at(-1).path, "/api/plugin/complex-rules/3");
  assert.equal(requests.at(-1).body.global, true);
  await send({ cmd: "complexDelete", accountId: "account1", id: 3 });
  assert.equal(requests.at(-1).method, "DELETE");
  await assert.rejects(send({ cmd: "complexRules", accountId: "account9" }), /nie jest zalogowane/);
  store.complexDraft = { accountId: "account1", created: Date.now(), rule: { action: "quarantine" } };
  assert.equal((await send({ cmd: "complexDraft" })).accountId, "account1");
  assert.equal(await send({ cmd: "complexDraft" }), null);
});

console.log(failures ? failures + " check(s) failed" : "all checks passed");
process.exit(failures ? 1 : 0);
