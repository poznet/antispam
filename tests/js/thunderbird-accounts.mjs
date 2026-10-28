// Per-account logins and accounts without a login (plugin 1.3.0), mocked WebExtension APIs.
//   node tests/js/thunderbird-accounts.mjs
// Exit code 0 = all checks passed. Run by ThunderbirdPluginJsTest (PHPUnit,
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
  try { await fn(); console.log("ok   " + name); } catch (e) { failures++; console.log("FAIL " + name + "\n     " + (e && e.stack)); }
}

const SERVER = "https://antispam.example.pl";
const quiet = { log() {}, warn() {}, error() {} };
const ACCOUNTS = [
  { id: "account1", name: "Jan (firma)", type: "imap", identities: [{ email: "Jan@Firma.pl" }] },
  { id: "account2", name: "Anna prywatna", type: "imap", identities: [{ email: "anna@inna.pl" }] },
  { id: "account3", name: "Lokalne foldery", type: "none", identities: [] },
];
const msg = (id, accountId, extra = {}) => Object.assign({ id, subject: "Tani towar " + id, author: "Spammer <spam@evil.top>", size: 2048, read: true, folder: { accountId, path: "/INBOX", name: "Inbox" } }, extra);

/**
 * Mocked Thunderbird. `server` options: reportOnly (status.report_only),
 * unauthorized (tokens answered with 401).
 */
function env(stored = {}, server = {}) {
  const store = Object.assign({ server: SERVER }, stored);
  const listeners = {};
  const calls = { optionsOpened: 0, requests: [], updates: [], moves: [], menuUpdates: [] };
  const ev = n => ({ addListener: f => (listeners[n] = f) });
  const messenger = {
    runtime: {
      getURL: p => "ext://" + p,
      getManifest: () => JSON.parse(read("manifest.json")),
      getBrowserInfo: async () => ({ name: "Thunderbird", version: "153.6.0" }),
      openOptionsPage: async () => { calls.optionsOpened++; },
      onMessage: ev("onMessage"), onInstalled: ev("onInstalled"),
      sendMessage: async m => listeners.onMessage(m),
    },
    storage: { local: {
      get: async k => { const o = {}; for (const x of [].concat(k)) if (x in store) o[x] = JSON.parse(JSON.stringify(store[x])); return o; },
      set: async o => { Object.assign(store, JSON.parse(JSON.stringify(o))); },
    } },
    permissions: { contains: async () => true, request: async () => true },
    notifications: { create: async () => {} },
    messageDisplayAction: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {}, onClicked: ev("btn") },
    messageDisplay: { getDisplayedMessages: async () => server.displayed || [] },
    mailTabs: { getSelectedMessages: async () => ({ id: null, messages: server.tabSelection || [] }) },
    messages: {
      getRaw: async () => "From: Spammer <spam@evil.top>\r\nSubject: x\r\n\r\nbody secret content",
      update: async (id, p) => { calls.updates.push([id, p]); },
      move: async (ids, f) => { calls.moves.push([ids, f]); },
      onNewMailReceived: ev("newMail"), onUpdated: ev("updated"), onMoved: ev("moved"), continueList: async () => null,
    },
    folders: { query: async ({ accountId }) => [{ id: accountId + "://Junk", path: "/Junk", accountId }] },
    accounts: {
      list: async () => ACCOUNTS,
      get: async id => ACCOUNTS.find(a => a.id === id) || null,
    },
    menus: { create: () => {}, onClicked: ev("menu"), onShown: ev("menuShown"), update: async (id, p) => { calls.menuUpdates.push([id, p]); }, refresh: async () => {} },
  };
  const fetch = async (url, opts = {}) => {
    if (url === "ext://config.json") throw new TypeError("no config.json");
    const auth = (opts.headers || {}).Authorization || "";
    const body = opts.body ? JSON.parse(opts.body) : null;
    const p = url.replace(SERVER, "");
    calls.requests.push({ path: p, auth, body });
    const json = data => ({ ok: true, status: 200, json: async () => data });
    if (server.unauthorized && auth && server.unauthorized.includes(auth.slice(7))) {
      return { ok: false, status: 401, json: async () => ({ error: "login required" }) };
    }
    if (p === "/api/plugin/status") {
      return json({ enabled: true, anonymous_reports: true, check_enabled: true, max_upload_bytes: 700 * 1024, phishing_max_bytes: 10485760,
        report_only: server.reportOnly !== false ? true : undefined, authenticated: !!auth, email: auth ? "x@y" : null });
    }
    if (p === "/api/plugin/report") return json({ verdict: body.verdict, sender: "spam@evil.top", signals: 1, rules: body.scope === "report_only" ? [] : ["email_blacklist_added:spam@evil.top"], scope: body.scope || "mailbox" });
    if (p === "/api/plugin/phishing") return json({ sender: "spam@evil.top", rules: [], phishing_id: 5, duplicate: false });
    if (p === "/api/plugin/check") return json({ decision: "spam", score: 9, spam_threshold: 5 });
    if (p === "/api/plugin/login") return json({ token: "TOK-" + body.email, email: body.email, expires_at: "2027-01-01T00:00:00+00:00" });
    if (p === "/api/plugin/ping") return json({ ok: true, client_ip: "1.2.3.4", received_at: "now" });
    return json({});
  };
  return { store, listeners, calls, messenger, fetch };
}

function load(e) {
  const src = read("common.js") + "\n" + read("background.js")
    + "\nreturn { settings, getLogins, contextFor, report, reportPhishing, reportHam, reportSpamAndFile, check, connectionTest };";
  return new Function("messenger", "fetch", "browser", "console", src)(e.messenger, e.fetch, e.messenger, quiet);
}

const logins = { account1: { token: "T1", email: "jan@firma.pl" } };
const reports = e => e.calls.requests.filter(r => r.path === "/api/plugin/report");
const settle = () => wait(30);

await check("1.2.x login is moved to the account with that e-mail", async () => {
  const e = env({ token: "OLD", email: "jan@firma.pl" });
  const bg = load(e);
  const l = await bg.getLogins();
  assert.deepEqual(Object.keys(l), ["account1"]);
  assert.equal(l.account1.token, "OLD");
  assert.equal(e.store.token, "");
  assert.equal(e.store.email, "");
});

await check("1.2.x login without a matching account becomes the general login", async () => {
  const e = env({ token: "OLD", email: "biuro@gdzie-indziej.pl" });
  const bg = load(e);
  const l = await bg.getLogins();
  assert.deepEqual(Object.keys(l), ["*"]);
  const ctx = await bg.contextFor("account2");
  assert.equal(ctx.kind, "report_only");
  assert.equal(ctx.login.email, "biuro@gdzie-indziej.pl");
});

await check("own account: report goes with its own token, no scope", async () => {
  const e = env({ logins: { account1: { token: "T1", email: "jan@firma.pl" }, account2: { token: "T2", email: "anna@inna.pl" } } });
  const bg = load(e);
  await bg.report(msg(1, "account2"), "spam", { manual: true });
  const r = reports(e)[0];
  assert.equal(r.auth, "Bearer T2");
  assert.equal(r.body.scope, undefined);
  assert.equal(r.body.reported_from, undefined);
});

await check("foreign account (report_only): another login authenticates, scope report_only + reported_from", async () => {
  const e = env({ logins });
  const bg = load(e);
  await bg.report(msg(1, "account2"), "spam", { manual: true });
  const r = reports(e)[0];
  assert.equal(r.auth, "Bearer T1");
  assert.equal(r.body.scope, "report_only");
  assert.deepEqual(r.body.reported_from, ["anna@inna.pl"]);
  await settle();
  const log = e.store.eventLog.find(x => x.kind === "result");
  assert.match(log.text, /tylko do administratora/);
  assert.match(log.detail, /konto: Anna prywatna <anna@inna.pl>/);
  assert.match(log.detail, /logowanie: jan@firma.pl/);
});

await check("foreign account, server without report_only: spam goes anonymously, phishing is not sent", async () => {
  const e = env({ logins }, { reportOnly: false });
  const bg = load(e);
  await bg.report(msg(1, "account2"), "spam", { manual: true });
  assert.equal(reports(e)[0].auth, "");
  await bg.reportPhishing(msg(2, "account2"));
  assert.equal(e.calls.requests.filter(r => r.path === "/api/plugin/phishing").length, 0);
  assert.equal(e.calls.optionsOpened, 1);
});

await check("foreign account (report_only): phishing authenticates with another login", async () => {
  const e = env({ logins });
  const bg = load(e);
  await bg.reportPhishing(msg(2, "account2"));
  const r = e.calls.requests.find(x => x.path === "/api/plugin/phishing");
  assert.equal(r.auth, "Bearer T1");
  assert.equal(r.body.scope, "report_only");
  assert.deepEqual(r.body.reported_from, ["anna@inna.pl"]);
  assert.ok(e.calls.updates.some(([id, p]) => id === 2 && p.junk === true), "filed as junk locally");
});

await check("foreign account (report_only): not-spam is refused locally, nothing sent", async () => {
  const e = env({ logins });
  const bg = load(e);
  await bg.reportHam(msg(3, "account2"));
  assert.equal(reports(e).length, 0);
  assert.equal(e.calls.optionsOpened, 1);
  await settle();
  assert.ok(e.store.eventLog.some(x => /To nie spam/.test(x.text) && !x.ok));
});

await check("linked mode: old behaviour - default login, no scope, ham allowed", async () => {
  const e = env({ logins, foreignMode: "linked" });
  const bg = load(e);
  await bg.reportHam(msg(3, "account2"));
  const r = reports(e)[0];
  assert.equal(r.auth, "Bearer T1");
  assert.equal(r.body.verdict, "ham");
  assert.equal(r.body.scope, undefined);
  assert.deepEqual(r.body.reported_from, ["anna@inna.pl"]);
});

await check("off mode: nothing is sent for foreign accounts, spam still filed locally", async () => {
  const e = env({ logins, foreignMode: "off" });
  const bg = load(e);
  await bg.reportSpamAndFile(msg(4, "account2"));
  await bg.reportPhishing(msg(5, "account2"));
  assert.equal(e.calls.requests.filter(r => r.path !== "/api/plugin/status").length, 0);
  assert.ok(e.calls.updates.some(([id, p]) => id === 4 && p.junk === true));
  assert.ok(e.calls.moves.length >= 1);
});

await check("no login at all: spam is anonymous as before, ham needs login", async () => {
  const e = env({});
  const bg = load(e);
  await bg.report(msg(1, "account1"), "spam", { manual: true });
  assert.equal(reports(e)[0].auth, "");
  assert.equal(reports(e)[0].body.reported_from, undefined, "no address in anonymous reports");
  await bg.reportHam(msg(2, "account1"));
  assert.equal(reports(e).length, 1);
});

await check("401 drops only the login of that account", async () => {
  const e = env({ logins: { account1: { token: "T1", email: "jan@firma.pl" }, account2: { token: "T2", email: "anna@inna.pl" } } }, { unauthorized: ["T2"] });
  const bg = load(e);
  await bg.report(msg(1, "account2"), "spam", { manual: true });
  const l = await bg.getLogins();
  assert.deepEqual(Object.keys(l), ["account1"]);
});

await check("new mail is checked only on accounts with their own login", async () => {
  const e = env({ logins });
  load(e);
  e.listeners.newMail({ accountId: "account2" }, { id: null, messages: [msg(10, "account2")] });
  e.listeners.newMail({ accountId: "account1" }, { id: null, messages: [msg(11, "account1")] });
  await wait(80);
  const checks = e.calls.requests.filter(r => r.path === "/api/plugin/check");
  assert.equal(checks.length, 1);
  assert.equal(checks[0].auth, "Bearer T1");
});

await check("menu click with empty selectedMessages falls back to the tab selection and logs the count", async () => {
  const e = env({ logins }, { tabSelection: [msg(20, "account1")] });
  load(e);
  e.listeners.menu({ menuItemId: "antispam-phishing", selectedMessages: { id: null, messages: [] } }, { id: 7 });
  await wait(80);
  assert.equal(e.calls.requests.filter(r => r.path === "/api/plugin/phishing").length, 1);
  assert.ok(e.store.eventLog.some(x => /Zaznaczono wiadomości: 1 \(zaznaczenie w karcie\)/.test(x.text)));
});

await check("menu click with nothing selected says so in the log", async () => {
  const e = env({ logins });
  load(e);
  e.listeners.menu({ menuItemId: "antispam-spam" }, { id: 7 });
  await wait(60);
  assert.ok(e.store.eventLog.some(x => /Nic nie zaznaczono/.test(x.text)));
});

await check("menu titles show the target; not-spam greyed out on a foreign account", async () => {
  const e = env({ logins });
  load(e);
  await e.listeners.menuShown({ menuIds: ["antispam-spam", "antispam-ham"], displayedFolder: { accountId: "account2" } });
  const ham = e.calls.menuUpdates.find(([id]) => id === "antispam-ham")[1];
  assert.equal(ham.enabled, false);
  assert.match(e.calls.menuUpdates.find(([id]) => id === "antispam-spam")[1].title, /tylko do administratora/);
});

await check("options bridge: per-account login, accounts list and logout", async () => {
  const e = env({});
  load(e);
  const res = await e.listeners.onMessage({ cmd: "login", accountId: "account2", email: "anna@inna.pl", password: "pw" });
  assert.equal(res.email, "anna@inna.pl");
  const state = await e.listeners.onMessage({ cmd: "accounts" });
  assert.deepEqual(state.accounts.map(a => a.id), ["account1", "account2"], "accounts without identities are skipped");
  assert.equal(state.accounts[1].login.email, "anna@inna.pl");
  assert.equal(state.accounts[1].login.token, undefined, "no token handed to the page");
  await e.listeners.onMessage({ cmd: "logout", accountId: "account2" });
  assert.deepEqual(e.store.logins, {});
});

await check("connection test per account pings with that account's token", async () => {
  const e = env({ logins: { account1: { token: "T1", email: "jan@firma.pl" }, account2: { token: "T2", email: "anna@inna.pl" } } });
  const bg = load(e);
  const res = await bg.connectionTest("account2");
  assert.ok(res.ok, JSON.stringify(res.steps));
  // 1.3.0 regression: the test's own step() shadowed the timeout helper
  assert.ok(!res.steps.some(x => /wersja Thunderbirda|permissions.contains/.test(x.name)), JSON.stringify(res.steps));
  assert.match(res.steps.find(x => x.name === "Wtyczka").text, /Thunderbird 153/);
  assert.equal(res.steps.find(x => x.name === "Zgoda na połączenie z serwerem").ok, true);
  const pings = e.calls.requests.filter(r => r.path === "/api/plugin/ping");
  assert.deepEqual(pings.map(p => p.auth), ["Bearer T2"]);
  e.calls.requests.length = 0;
  await bg.connectionTest("all");
  assert.deepEqual(e.calls.requests.filter(r => r.path === "/api/plugin/ping").map(p => p.auth), ["Bearer T1", "Bearer T2"]);
});

await check("event log never contains tokens, passwords or the message body", async () => {
  const e = env({ logins });
  const bg = load(e);
  await e.listeners.onMessage({ cmd: "login", accountId: "account2", email: "anna@inna.pl", password: "SECRET-PW" });
  await bg.report(msg(1, "account2"), "spam", { manual: true });
  await bg.reportPhishing(msg(2, "account1"));
  await settle();
  const dump = JSON.stringify(e.store.eventLog);
  assert.ok(!dump.includes("T1"), "token T1");
  assert.ok(!dump.includes("TOK-"), "issued token");
  assert.ok(!dump.includes("SECRET-PW"), "password");
  assert.ok(!dump.includes("secret content"), "message body");
  assert.match(dump, /\(\d+ ms\)/, "request durations");
});

/**
 * Thunderbird API promises that never settle (seen in 1.2.1: "spam can be
 * reported only once after a restart"): every later click must still work.
 * Timers run 1000x faster here (setTimeout passed into the script scope).
 */
function loadFast(e) {
  const fast = (fn, ms, ...a) => setTimeout(fn, Math.max(1, Math.round((ms || 0) / 1000)), ...a);
  const src = read("common.js") + "\n" + read("background.js") + "\nreturn { reportSpamAndFile };";
  return new Function("messenger", "fetch", "browser", "setTimeout", "console", src)(e.messenger, e.fetch, e.messenger, fast, quiet);
}
const never = () => new Promise(() => {});

await check("hung move / junk flag / notification: ten clicks in a row all send their report", async () => {
  const e = env({ logins });
  e.messenger.messages.move = never;
  e.messenger.messages.update = never;
  e.messenger.notifications.create = never;
  e.messenger.messageDisplayAction.setBadgeText = never;
  loadFast(e);
  for (let i = 1; i <= 10; i++) {
    e.listeners.menu({ menuItemId: "antispam-spam", selectedMessages: { id: null, messages: [msg(100 + i, "account1")] } }, { id: 1 });
  }
  for (let i = 0; i < 100 && reports(e).length < 10; i++) await wait(20);
  assert.equal(reports(e).length, 10);
  await wait(100);
  assert.ok(e.store.eventLog.some(x => /Zadanie zawieszone na kroku .*messages\.(update|move)/.test(x.text)), "the hung step is logged");
});

await check("hung getRaw: the click gives up, the next one still runs", async () => {
  const e = env({ logins });
  let calls = 0;
  e.messenger.messages.getRaw = async () => (++calls === 1 ? never() : "From: a@b\r\n\r\nx");
  loadFast(e);
  e.listeners.menu({ menuItemId: "antispam-phishing", selectedMessages: { id: null, messages: [msg(201, "account1")] } }, { id: 1 });
  e.listeners.menu({ menuItemId: "antispam-phishing", selectedMessages: { id: null, messages: [msg(202, "account1")] } }, { id: 1 });
  for (let i = 0; i < 100 && !e.calls.requests.some(r => r.path === "/api/plugin/phishing"); i++) await wait(20);
  assert.equal(e.calls.requests.filter(r => r.path === "/api/plugin/phishing").length, 1);
  await wait(50);
  assert.ok(e.store.eventLog.some(x => /messages\.getRaw/.test(x.text) && !x.ok));
});

await check("several selected messages, clicks while the previous one still runs", async () => {
  const e = env({ logins });
  let release;
  const slow = new Promise(r => { release = r; });
  e.messenger.messages.move = () => slow;
  loadFast(e);
  e.listeners.menu({ menuItemId: "antispam-spam", selectedMessages: { id: null, messages: [msg(301, "account1"), msg(302, "account2"), msg(303, "account1")] } }, { id: 1 });
  e.listeners.btn({ id: 1 });
  e.messenger.messageDisplay.getDisplayedMessages = async () => [msg(304, "account1")];
  e.listeners.menu({ menuItemId: "antispam-spam", selectedMessages: { id: null, messages: [msg(305, "account1")] } }, { id: 1 });
  for (let i = 0; i < 100 && reports(e).length < 5; i++) await wait(20);
  release();
  assert.equal(reports(e).length, 5);
  assert.equal(reports(e).filter(r => r.body.scope === "report_only").length, 1, "message of the account without a login");
});

if (failures) {
  console.log(failures + " check(s) failed");
  process.exit(1);
}
console.log("all checks passed");
