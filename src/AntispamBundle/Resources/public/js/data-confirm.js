/*
 * Confirmation prompts without inline handlers (CSP-safe): any link or button with
 * data-confirm="Question?" asks first and cancels the click when the user says no.
 */
(function () {
    document.addEventListener('click', function (e) {
        var el = e.target && e.target.closest ? e.target.closest('[data-confirm]') : null;
        if (el && !window.confirm(el.getAttribute('data-confirm'))) {
            e.preventDefault();
            e.stopImmediatePropagation();
        }
    }, true);
})();
