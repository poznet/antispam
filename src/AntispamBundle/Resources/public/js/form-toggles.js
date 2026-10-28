/*
 * Small form helpers without inline handlers (CSP-safe):
 * - account add/edit: #connectionType shows #imapFields or #sshFields,
 * - user form: #userRole dims #accountsPanel for administrators (they see every mailbox anyway).
 */
(function () {
    var type = document.getElementById('connectionType');
    if (type) {
        type.addEventListener('change', function () {
            var imap = document.getElementById('imapFields');
            var ssh = document.getElementById('sshFields');
            if (imap) { imap.style.display = type.value === 'imap' ? 'block' : 'none'; }
            if (ssh) { ssh.style.display = type.value === 'ssh' ? 'block' : 'none'; }
        });
    }

    var role = document.getElementById('userRole');
    var panel = document.getElementById('accountsPanel');
    if (role && panel) {
        var dim = function () { panel.style.opacity = role.value === 'ROLE_ADMIN' ? '0.5' : '1'; };
        role.addEventListener('change', dim);
        dim();
    }
})();
