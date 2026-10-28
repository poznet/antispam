/*
 * "Zaznacz wszystkie" without inline handlers (CSP-safe): a checkbox with
 * data-check-all="<form id>" toggles every enabled checkbox of that form
 * (nested in it or attached with the form="<form id>" attribute).
 */
(function () {
    document.addEventListener('change', function (e) {
        var all = e.target;
        if (!all || !all.hasAttribute || !all.hasAttribute('data-check-all')) {
            return;
        }
        var form = document.getElementById(all.getAttribute('data-check-all'));
        if (!form) {
            return;
        }
        var boxes = form.elements;
        for (var i = 0; i < boxes.length; i++) {
            if (boxes[i] !== all && boxes[i].type === 'checkbox' && !boxes[i].disabled) {
                boxes[i].checked = all.checked;
            }
        }
    });
})();
