/* Panel: "Reguły złożone" form - mounts ComplexRuleBuilder and writes the tree to the hidden field on submit. */
(function () {
  "use strict";
  var box = document.getElementById("cr-builder");
  var field = document.getElementById("cr-conditions");
  var form = document.getElementById("complex-rule-form");
  if (!box || !field || !form || !window.ComplexRuleBuilder) return;
  var tree = null;
  try { tree = JSON.parse(field.value); } catch (e) { tree = null; }
  var builder = window.ComplexRuleBuilder.mount(box, {
    vocab: JSON.parse(box.getAttribute("data-vocab") || "{}"),
    tree: tree,
    classes: { input: "form-control input-sm", button: "btn btn-default btn-xs", danger: "btn-danger" },
  });
  form.addEventListener("submit", function () {
    field.value = JSON.stringify(builder.getTree());
  });
  var action = document.getElementById("cr-action");
  var score = document.getElementById("cr-score");
  var defaults = (JSON.parse(box.getAttribute("data-vocab") || "{}").default_scores) || {};
  if (action && score) {
    var sync = function () {
      var noPoints = action.value === "whitelist" || action.value === "log";
      score.disabled = noPoints;
      if (noPoints) score.value = 0;
    };
    action.addEventListener("change", function () {
      if (defaults[action.value] !== undefined) score.value = defaults[action.value];
      sync();
    });
    sync();
  }
})();
