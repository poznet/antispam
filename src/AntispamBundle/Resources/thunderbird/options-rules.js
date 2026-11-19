/*
 * Settings page: "Reguły złożone" (1.6.0, docs/complex-rules.md). Loaded
 * after options.js (uses its $, el, send, show, errorText) and
 * complex-rule-builder.js. Rules live on the server; every call goes through
 * the background script (cmd complexRules / complexSave / complexDelete /
 * complexDraft), which logs it in the event log.
 */
"use strict";

const rules = { accountId: "", data: null, editing: null, builder: null, draft: null };

function ruleTagClass(action) {
  return { spam: "spam", quarantine: "quarantine", whitelist: "whitelist" }[action] || "";
}

function renderRuleActions(data) {
  const sel = $("ruleAction");
  sel.textContent = "";
  for (const [k, label] of Object.entries((data && data.actions) || {})) sel.appendChild(el("option", { value: k, textContent: label }));
}

function syncScore(changedAction) {
  const action = $("ruleAction").value;
  const defaults = (rules.data && rules.data.default_scores) || {};
  if (changedAction && defaults[action] !== undefined) $("ruleScore").value = defaults[action];
  const noPoints = action === "whitelist" || action === "log";
  $("ruleScore").disabled = noPoints;
  if (noPoints) $("ruleScore").value = 0;
}
$("ruleAction").addEventListener("change", () => syncScore(true));

function renderRules() {
  const box = $("rulesList");
  box.textContent = "";
  const data = rules.data;
  if (!data) return;
  $("rulesInfo").textContent = "Skrzynka " + data.mailbox + " - " + data.rules.length + " reguł (własne i globalne)"
    + (data.can_global ? "; możesz tworzyć reguły dla wszystkich skrzynek." : "; reguły globalne tworzy administrator.");
  if (!data.rules.length) {
    box.appendChild(el("p", { className: "muted" }, "Brak reguł złożonych dla tej skrzynki."));
  }
  for (const r of data.rules) {
    const head = el("div", {},
      el("strong", {}, r.name || "(bez nazwy)"),
      el("span", { className: "tag " + ruleTagClass(r.action) }, ((data.actions || {})[r.action] || r.action) + (["spam", "quarantine", "score"].includes(r.action) ? " · " + r.score + " pkt" : "")),
      r.global ? el("span", { className: "tag global" }, "wszystkie skrzynki") : null,
      r.enabled ? null : el("span", { className: "tag" }, "wyłączona"),
      el("span", { className: "muted" }, " " + (r.counter || 0) + " trafień"));
    const buttons = el("div", { className: "buttons" });
    if (r.editable) {
      buttons.appendChild(el("button", { type: "button", className: "secondary", on: { click: () => openEditor(r) } }, "Edytuj"));
      buttons.appendChild(el("button", { type: "button", className: "secondary", on: { click: () => toggleRule(r) } }, r.enabled ? "Wyłącz" : "Włącz"));
      buttons.appendChild(el("button", { type: "button", className: "secondary", on: { click: () => deleteRule(r) } }, "Usuń"));
    } else {
      buttons.appendChild(el("span", { className: "muted" }, "zmienia administrator w panelu"));
    }
    box.appendChild(el("div", { className: "rule-item" + (r.enabled ? "" : " off") }, head, el("div", { className: "rule-desc" }, r.description || ""), buttons));
  }
}

async function loadRules() {
  $("ruleEditor").hidden = true;
  rules.data = null;
  $("rulesList").textContent = "";
  $("ruleNew").disabled = true;
  if (!rules.accountId) {
    $("rulesInfo").textContent = "Zaloguj konto w sekcji „Konta”, aby tworzyć reguły jego skrzynki.";
    return;
  }
  $("rulesInfo").textContent = "Wczytywanie reguł…";
  try {
    rules.data = await send({ cmd: "complexRules", accountId: rules.accountId });
    renderRuleActions(rules.data);
    $("ruleNew").disabled = false;
    renderRules();
    if (rules.draft && rules.draft.accountId === rules.accountId) {
      const d = rules.draft;
      rules.draft = null;
      openEditor(Object.assign({ id: 0 }, d.rule), "Nowa reguła z wiadomości: " + (d.subject || d.from || ""));
      $("rules").scrollIntoView({ behavior: "smooth" });
    }
  } catch (e) {
    $("rulesInfo").textContent = "";
    show($("rulesMsg"), "Nie udało się wczytać reguł: " + errorText(e), false);
  }
}

function openEditor(rule, title) {
  const data = rules.data;
  rules.editing = rule;
  $("ruleEditorTitle").textContent = title || (rule.id ? "Edycja reguły: " + rule.name : "Nowa reguła");
  $("ruleName").value = rule.name || "";
  $("ruleScope").value = rule.global ? "global" : "local";
  $("ruleScope").querySelector('option[value="global"]').disabled = !data.can_global && !rule.global;
  $("ruleAction").value = rule.action || "quarantine";
  $("ruleScore").value = rule.score === undefined ? "" : rule.score;
  $("ruleEnabled").checked = rule.enabled !== false;
  syncScore(rule.score === undefined);
  rules.builder = globalThis.ComplexRuleBuilder.mount($("ruleBuilder"), {
    vocab: data,
    tree: rule.conditions || null,
    classes: { button: "secondary", danger: "danger" },
  });
  $("ruleMsg").hidden = true;
  $("ruleEditor").hidden = false;
}

$("ruleNew").addEventListener("click", () => openEditor({ id: 0, action: "quarantine", enabled: true }));
$("ruleCancel").addEventListener("click", () => { $("ruleEditor").hidden = true; });

$("ruleSave").addEventListener("click", async () => {
  const r = rules.editing || { id: 0 };
  const rule = {
    id: r.id || 0,
    name: $("ruleName").value.trim(),
    global: $("ruleScope").value === "global",
    action: $("ruleAction").value,
    score: $("ruleScore").value,
    enabled: $("ruleEnabled").checked,
    conditions: rules.builder.getTree(),
  };
  $("ruleSave").disabled = true;
  try {
    await send({ cmd: "complexSave", accountId: rules.accountId, rule });
    show($("rulesMsg"), "Reguła zapisana na serwerze - działa od razu.", true);
    await loadRules();
  } catch (e) {
    show($("ruleMsg"), "Nie zapisano: " + errorText(e), false);
  } finally {
    $("ruleSave").disabled = false;
  }
});

async function toggleRule(r) {
  try {
    await send({ cmd: "complexSave", accountId: rules.accountId, rule: { id: r.id, name: r.name, global: r.global, action: r.action, score: r.score, enabled: !r.enabled, conditions: r.conditions } });
    await loadRules();
  } catch (e) {
    show($("rulesMsg"), "Nie udało się zmienić reguły: " + errorText(e), false);
  }
}

async function deleteRule(r) {
  // No confirm(): a modal dialog in the options tab is fine, but keep it one click away -
  // the button turns into "Na pewno?" first.
  const key = "del-" + r.id;
  if (rules.confirm !== key) {
    rules.confirm = key;
    show($("rulesMsg"), "Kliknij „Usuń” jeszcze raz, aby usunąć regułę „" + r.name + "”.", false);
    setTimeout(() => { if (rules.confirm === key) rules.confirm = null; }, 5000);
    return;
  }
  rules.confirm = null;
  try {
    await send({ cmd: "complexDelete", accountId: rules.accountId, id: r.id });
    show($("rulesMsg"), "Usunięto regułę „" + r.name + "”.", true);
    await loadRules();
  } catch (e) {
    show($("rulesMsg"), "Nie udało się usunąć: " + errorText(e), false);
  }
}

$("rulesAccount").addEventListener("change", () => {
  rules.accountId = $("rulesAccount").value;
  loadRules();
});

/** Called by options.js after every accounts refresh (login / logout). */
globalThis.rulesAccountsChanged = function (state) {
  const sel = $("rulesAccount");
  const logged = ((state && state.accounts) || []).filter(a => a.login);
  const previous = rules.accountId;
  sel.textContent = "";
  if (!logged.length) sel.appendChild(el("option", { value: "" }, "(brak zalogowanych kont)"));
  for (const a of logged) sel.appendChild(el("option", { value: a.id }, a.name + " - " + a.login.email));
  const want = (rules.draft && logged.some(a => a.id === rules.draft.accountId)) ? rules.draft.accountId
    : logged.some(a => a.id === previous) ? previous : (logged[0] ? logged[0].id : "");
  sel.value = want;
  if (want !== previous || !rules.data) {
    rules.accountId = want;
    loadRules();
  }
};

// Draft from the message menu ("Utwórz regułę złożoną z tej wiadomości").
send({ cmd: "complexDraft" }).then(d => {
  if (!d) return;
  rules.draft = d;
  if (rules.accountId === d.accountId && rules.data) loadRules();
  else if ([...$("rulesAccount").options].some(o => o.value === d.accountId)) {
    $("rulesAccount").value = d.accountId;
    rules.accountId = d.accountId;
    loadRules();
  } else {
    show($("rulesMsg"), "Konto wiadomości nie jest zalogowane we wtyczce - zaloguj je, a szkic reguły zostanie otwarty.", false);
  }
}).catch(() => { /* older background */ });
