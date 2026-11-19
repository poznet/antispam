/*
 * Complex rule builder (docs/complex-rules.md) - AND / OR groups of
 * conditions. Framework-free, no innerHTML: shared by the panel
 * (Resources/public/js) and the Thunderbird plugin (Resources/thunderbird);
 * the two copies must stay identical (ComplexRuleBuilderSyncTest).
 *
 *   const b = ComplexRuleBuilder.mount(container, { vocab, tree, classes });
 *   b.getTree()  -> {op, negate, items: [...]}
 *
 * vocab = the "fields" / "matches" / "number_matches" / "limits" part of
 * GET /api/plugin/complex-rules (ComplexRuleService::vocabulary()).
 */
(function (root) {
  "use strict";

  function h(tag, props, children) {
    const e = document.createElement(tag);
    for (const k of Object.keys(props || {})) {
      const v = props[k];
      if (k === "on") for (const t of Object.keys(v)) e.addEventListener(t, v[t]);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else if (v !== undefined && v !== null) e[k] = v;
    }
    for (const c of children || []) {
      if (c === null || c === undefined || c === false) continue;
      e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    }
    return e;
  }

  let uid = 0;

  function mount(container, opts) {
    const vocab = opts.vocab || {};
    const fields = vocab.fields || [];
    const matches = vocab.matches || {};
    const numberMatches = vocab.number_matches || ["lt", "gt", "equals", "empty"];
    const limits = vocab.limits || { depth: 4, conditions: 30, value: 500 };
    const cls = Object.assign({ input: "", button: "", danger: "", group: "" }, opts.classes || {});
    const fieldMeta = {};
    for (const f of fields) fieldMeta[f.key] = f;

    function blankCondition() {
      return { field: "subject", match: "contains", value: "", negate: false };
    }
    function normalizeTree(t) {
      if (!t || typeof t !== "object") return { op: "and", negate: false, items: [blankCondition()] };
      if (!t.op) return { op: "and", negate: false, items: [t] };
      return t;
    }

    let tree = JSON.parse(JSON.stringify(normalizeTree(opts.tree)));
    if (!tree.items || !tree.items.length) tree.items = [blankCondition()];

    function countConditions(node) {
      if (node.op) return (node.items || []).reduce((n, c) => n + countConditions(c), 0);
      return 1;
    }

    function changed() {
      render();
      if (typeof opts.onChange === "function") opts.onChange(tree);
    }

    function matchOptions(field) {
      const isNumber = (fieldMeta[field] || {}).type === "number";
      const keys = Object.keys(matches).filter(k => isNumber ? numberMatches.includes(k) : !["lt", "gt"].includes(k));
      const out = [];
      for (const k of keys) {
        const labels = matches[k] || [k, "nie " + k];
        out.push({ value: k + "|0", label: labels[0] });
        out.push({ value: k + "|1", label: labels[1] });
      }
      return out;
    }

    function conditionRow(node, parent, index) {
      const meta = fieldMeta[node.field] || {};
      const fieldSel = h("select", { className: cls.input, title: "Pole", on: { change: e => {
        node.field = e.target.value;
        const m = fieldMeta[node.field] || {};
        const allowed = matchOptions(node.field).map(o => o.value.split("|")[0]);
        if (!allowed.includes(node.match)) node.match = m.type === "number" ? "lt" : "contains";
        if (node.field !== "header") delete node.header;
        changed();
      } } }, fields.map(f => h("option", { value: f.key, textContent: f.label + (f.server || f.network ? " ⌁" : ""), selected: f.key === node.field })));

      const matchSel = h("select", { className: cls.input, title: "Dopasowanie", on: { change: e => {
        const [m, neg] = e.target.value.split("|");
        node.match = m;
        node.negate = neg === "1";
        if (m === "empty") delete node.value;
        changed();
      } } }, matchOptions(node.field).map(o => h("option", { value: o.value, textContent: o.label, selected: o.value === node.match + "|" + (node.negate ? "1" : "0") })));

      let header = null;
      if (node.field === "header") {
        header = h("input", { type: "text", className: cls.input, placeholder: "nazwa nagłówka, np. X-Mailer", value: node.header || "", maxLength: 76, size: 18,
          on: { input: e => { node.header = e.target.value.trim(); } } });
      }

      let value = null;
      if (node.match !== "empty") {
        let list = null;
        const suggest = meta.suggest || [];
        if (suggest.length) {
          const id = "crb-list-" + (++uid);
          list = h("datalist", { id }, suggest.map(s => h("option", { value: s })));
          value = h("input", { type: "text", className: cls.input, value: node.value || "", maxLength: limits.value || 500, size: 22,
            placeholder: suggest.slice(0, 3).join(", ") + "…", on: { input: e => { node.value = e.target.value; } } });
          value.setAttribute("list", id);
        } else {
          value = h("input", { type: meta.type === "number" ? "number" : "text", className: cls.input, value: node.value || "", maxLength: limits.value || 500, size: 26,
            placeholder: node.match === "wildcard" ? "np. *faktura*" : node.match === "regex" ? "np. ^pilne.*przelew" : meta.type === "number" ? "liczba" : "tekst",
            on: { input: e => { node.value = e.target.value; } } });
        }
        if (list) value = h("span", {}, [value, list]);
      }

      const del = h("button", { type: "button", className: cls.button + " " + cls.danger, textContent: "✕", title: "Usuń warunek",
        on: { click: () => { parent.items.splice(index, 1); changed(); } } });
      const hint = meta.server || meta.network ? h("small", { className: "crb-hint", textContent: meta.network ? "sprawdzane tylko na serwerze (DNS / WHOIS)" : "sprawdzane tylko na serwerze" }) : null;
      return h("div", { className: "crb-cond" }, [fieldSel, header, matchSel, value, del, hint]);
    }

    function groupBox(node, parent, index, depth) {
      const opSel = h("select", { className: cls.input, on: { change: e => { node.op = e.target.value; changed(); } } }, [
        h("option", { value: "and", textContent: "wszystkie warunki (I)", selected: node.op === "and" }),
        h("option", { value: "or", textContent: "dowolny warunek (LUB)", selected: node.op === "or" }),
      ]);
      const neg = h("label", { className: "crb-neg", title: "Odwróć wynik całej grupy (wyjątek: NIE …)" }, [
        h("input", { type: "checkbox", checked: !!node.negate, on: { change: e => { node.negate = e.target.checked; changed(); } } }),
        " NIE (odwróć)",
      ]);
      const total = countConditions(tree);
      const full = total >= (limits.conditions || 30);
      const addCond = h("button", { type: "button", className: cls.button, textContent: "+ warunek", disabled: full,
        on: { click: () => { node.items.push(blankCondition()); changed(); } } });
      const addGroup = depth < (limits.depth || 4) ? h("button", { type: "button", className: cls.button, textContent: "+ grupa", disabled: full,
        on: { click: () => { node.items.push({ op: node.op === "and" ? "or" : "and", negate: false, items: [blankCondition()] }); changed(); } } }) : null;
      const delGroup = parent ? h("button", { type: "button", className: cls.button + " " + cls.danger, textContent: "usuń grupę",
        on: { click: () => { parent.items.splice(index, 1); changed(); } } }) : null;

      const items = h("div", { className: "crb-items" });
      (node.items || []).forEach((child, i) => {
        if (i > 0) items.appendChild(h("div", { className: "crb-join", textContent: node.op === "and" ? "I" : "LUB" }));
        items.appendChild(child.op ? groupBox(child, node, i, depth + 1) : conditionRow(child, node, i));
      });
      return h("div", { className: "crb-group " + cls.group + (depth > 1 ? " crb-nested" : "") }, [
        h("div", { className: "crb-head" }, [h("span", { textContent: depth > 1 ? "Grupa: " : "Spełnione muszą być " }), opSel, neg, addCond, addGroup, delGroup]),
        items,
      ]);
    }

    function render() {
      container.textContent = "";
      container.appendChild(groupBox(tree, null, 0, 1));
    }

    render();
    return {
      getTree() {
        return JSON.parse(JSON.stringify(tree));
      },
      setTree(t) {
        tree = JSON.parse(JSON.stringify(normalizeTree(t)));
        if (!tree.items || !tree.items.length) tree.items = [blankCondition()];
        render();
      },
    };
  }

  root.ComplexRuleBuilder = { mount };
})(typeof globalThis !== "undefined" ? globalThis : this);
