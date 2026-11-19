# Complex rules ("Reguły złożone")

Rules built from conditions joined with **I** (AND) / **LUB** (OR), with
nested groups and negation, e.g.

> temat zawiera „faktura” **I** treść **nie** zawiera „umowa” **I** (wiek
> domeny nadawcy < 30 dni **LUB** załącznik pasuje do regex `\.exe$`) → kwarantanna

They complement the white / blacklists (which only look at the sender) and run
on the **server**: the IMAP pipeline (scan, rescan, folder pass), the SSH +
Maildir agent (3.8+) and the plugin checks (`/api/plugin/check`). The
Thunderbird plugin (1.6.0+) also evaluates them locally in *Zastosuj reguły
antyspamu w tym folderze*.

Where they are managed:

- **Panel → Blacklisty → Reguły złożone** (`/complex-rules`, admin): list, rule
  builder, enable / disable, delete, *Testuj na wiadomości* (paste a message
  source: which rules of a mailbox match, and every field value the rules see -
  nothing is counted or moved), switch for the network lookups.
- **Thunderbird plugin → Ustawienia → Reguły złożone** (logged-in accounts):
  the same builder; *lokalna* = the account's mailbox, *globalna* = every
  mailbox (only when the admin allows it). The message context menu has
  *Utwórz regułę złożoną z tej wiadomości…*, which opens the settings with a
  draft (sender domain + subject). Rules created there are stored on the
  server at once (source `plugin`, `created_by = plugin:<mailbox>`) and show up
  in the panel with the label *wtyczka*.

Code: `Services/ComplexRuleEngine` (validation, evaluation), `ComplexRuleMessage`
(field values of a message), `SenderIntelService` (MX / domain age lookups),
`ComplexRuleService` (loading per mailbox, actions, input), listener
`EventListener/Message/CheckComplexRules`, entity `ComplexRule` (table
`antispam_complex_rule`, migration `Version20261119120000`). Agent: `complex*()`
in `antispam-agent.php`. Plugin: `complexEval()` / `complexProvider()` in
`background.js`, page `options-rules.js`, builder `complex-rule-builder.js`
(identical copy in `Resources/public/js`, checked by a test).

## Condition tree

```json
{"op": "and", "negate": false, "items": [
  {"field": "subject", "match": "contains", "value": "faktura"},
  {"field": "body", "match": "contains", "value": "umowa", "negate": true},
  {"op": "or", "items": [
    {"field": "domain_age", "match": "lt", "value": "30"},
    {"field": "attachment", "match": "regex", "value": "\\.exe$"}
  ]}
]}
```

- `op`: `and` (all) / `or` (any); `negate` on a group = *NIE (…)* (exceptions).
- At most 4 levels, 30 conditions, 500 characters per value.
- Values are compared lower-cased, with whitespace runs folded to one space
  (`fold()`), the pattern likewise (regex: only trimmed).
- A field with several values (to, reply_to, header, attachment, link_domain,
  mx_host…) matches when **any** value matches; negated when **none** does.
  A missing field has no values: `contains` is false, `nie zawiera` true,
  `jest puste` true.

### Match types

| `match` | Meaning | negated |
|---|---|---|
| `contains` | substring | nie zawiera |
| `equals` | whole value | nie jest równe |
| `starts` / `ends` | prefix / suffix | |
| `wildcard` | shell glob over the **whole** value: `*` any string, `?` one character (`*faktura*`, `*.ru`) | |
| `regex` | PCRE without delimiters, case-insensitive, searches anywhere; invalid or too expensive (backtracking limit, `(a+)+$`) patterns are refused when saved | |
| `empty` | no value / empty | nie jest puste / istnieje |
| `lt` / `gt` | numbers only (number fields) | |

### Fields

| `field` | Value | Needs |
|---|---|---|
| `from`, `from_domain`, `from_name` | From address (lower-cased), its domain, display name (decoded) | headers |
| `to` | addresses in To + Cc | headers |
| `reply_to`, `return_path` | addresses | headers |
| `from_scope` | `internal` (same registered domain as the mailbox) / `external` | headers |
| `from_freemail` | `tak` / `nie` (gmail, outlook, wp.pl, onet, interia, o2…; `DomainHelper::freemailList()`) | headers |
| `subject` | decoded subject | headers |
| `header` + `header` name | every value of that header (e.g. `X-Mailer`, `List-Id`) | headers |
| `message_type` | `autoreply`, `bounce`, `readreceipt`, `list`, `calendar`, `signed`, `encrypted` - from the top-level headers (an invitation inside multipart/alternative: use `attachment_type = text/calendar`) | headers |
| `auth_spf`, `auth_dkim`, `auth_dmarc` | results in the topmost `Authentication-Results` (the receiving server's, like `HeaderAnalyzer`); SPF falls back to `Received-SPF`. Two DKIM signatures = two values | headers |
| `sender_ip` | first public IP of the trusted Received hops (`RawMessageParser::getConnectingIp()`) | headers, server only |
| `size_kb` (number) | message size, KiB rounded up | IMAP size / file size |
| `body` | plain text (or stripped HTML), first 256 KiB | body |
| `attachment`, `attachment_type`, `attachment_count` (number) | file names, MIME types, count | body |
| `link_domain` | hosts of the links in the body | body |
| `mx_provider` | provider of the From domain's mail by its MX hosts: `google`, `microsoft`, `zoho`, `proton`, `yahoo`, `icloud`, `yandex`, `mailru`, `fastmail`, `ovh`, `homepl`, `nazwapl`, `cyberfolks`, `lh`, `zenbox`, `wp`, `onet`, `interia`, `o2`, `mimecast`, `proofpoint`, `barracuda`, `other`, `none` (no MX) | DNS, server only |
| `mx_host` | MX hosts of the From domain | DNS, server only |
| `domain_age` (number) | age of the registered From domain in days | RDAP / WHOIS, server only |

Header fields cost nothing extra. Body fields download the message in IMAP
mode only when a rule of the mailbox uses them (the pipeline otherwise reads
the header block only).

### Sender domain lookups

`SenderIntelService` (agent: `complexMxHosts()` / `complexDomainAgeDays()`):

- **MX**: `dns_get_record(DNS_MX)` of the From domain, cached 1 day; a failed
  lookup (timeout, SERVFAIL) is "unknown" (no value), not `none`.
- **Domain age**: RDAP via `https://rdap.org/domain/<registered domain>`
  (redirects to the registry), the `registration` event; registries without
  RDAP: WHOIS port 43 - the server from `whois.iana.org`, then the `created:` /
  `Creation Date:` line. Cached 7 days, failures 6 hours. Only the sender's
  domain leaves the server.
- Cache: the app cache pool (`antispam_intel.*`) on the server, table
  `intel_cache` in the agent's SQLite.
- Off: *Reguły złożone → Zapytania o domenę nadawcy* (`complex.lookups = 0`,
  synced to agents as `complex_lookups`). Then these fields have no value.

The plugin cannot do DNS / WHOIS nor pick the trusted Received hop: rules with
`mx_provider`, `mx_host`, `domain_age` or `sender_ip` are skipped in its local
folder pass (logged as *tylko na serwerze*) and decided by the server.

## Actions and order

| `action` | Effect | Points |
|---|---|---|
| `spam` | always spam (like a blacklist hit) | its score is added (shown in the score log), 0…50 |
| `quarantine` | at least quarantine, whatever the score (`MessageEvent::setForcedQuarantine()`, `classify(..., $forcedQuarantine)`) | 0…50 |
| `score` | adds its points (negative lowers the score), −50…50; ignored with scoring off | |
| `whitelist` | the message is whitelisted, nothing else runs | 0 |
| `log` | test mode: only a 0-point reason in the score log | 0 |

Order (server, agent, plugin): white lists → complex `whitelist` rules (first
match wins) → blacklists → every other complex rule (all matching ones apply)
→ header heuristics, DNSBL, links, … → decision. Pipeline priorities:
`CheckComplexRules::whitelist` 99998, `::check` 99995.

Score log reason: `complex_rule:#<id> <name> (<action>)`. Hit counters as for
the lists (not on initial scans / rescans).

## Ownership and limits

Like the lists ([scoring.md](scoring.md#rule-ownership)): `email` = a mailbox
or `*` (every mailbox). 200 rules per owner.

Plugin (`plugin.complex_rules`, default on; `plugin.global_rules`, default
**off**, *Ustawienia → Wtyczki pocztowe*):

- a logged-in mailbox lists its own and the global rules and edits its own;
- global rules: created / moved to global only with `plugin.global_rules`,
  and editable from the plugin only when created by that mailbox from the
  plugin (`created_by = plugin:<mailbox>`); admin rules are read-only there;
- rules of other mailboxes are invisible (404);
- 120 changes per account and hour; every change is audited (`rule.add` /
  `rule.update` / `rule.delete`, target `complex_rule`, actor = the mailbox).

Every change queues a rules push to the SSH agents concerned
(`DeferredAgentSync`: the owner's account, all agents for global rules).

## Plugin API

`Authorization: Bearer <token>`; `403` when disabled, `401` without login.

| Method | URL | Body / answer |
|---|---|---|
| GET | `/api/plugin/complex-rules` | `{mailbox, can_global, rules: [{id, name, enabled, action, score, conditions, description, global, owner, counter, source, created_by, updated_at, editable}], fields, matches, number_matches, actions, default_scores, limits}` |
| POST | `/api/plugin/complex-rules` | `{name?, enabled?, action, score?, conditions, global?}` → `201 {rule}`; `400 {message, errors}` invalid, `403` global not allowed, `409` limit |
| PUT | `/api/plugin/complex-rules/{id}` | same fields (missing = unchanged; `global` moves the rule) → `{rule}`; `403` not editable, `404` not visible |
| DELETE | `/api/plugin/complex-rules/{id}` | `{deleted}` |

`GET /api/plugin/rules` also returns `complex_rules` (enabled rules of the
mailbox) and `freemail` (domains for `from_freemail`); `/status` returns
`complex_rules` and `complex_rules_global`.

## Agent (3.8)

`rules.json` section `complex_rules: [{id, email, name, action, score,
conditions}]` (the mailbox's enabled rules + global), table `complex_rules`;
`settings.complex_lookups` and `settings.mailbox_email` (for `from_scope`).
An agent before 3.8 ignores the section (redeploy: *Konta → Wdróż*).
`ComplexRuleAgentParityTest` keeps the agent's field values and verdicts equal
to the web side.

## Backup

`antispam:export` / `/backup` write them as `rules.complex: [{owner, name,
enabled, action, score, conditions, source, created_by, hits}]`; import matches
by owner + name + conditions (merge updates action / score / enabled, replace
also removes the ones not in the file).
