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

    // IMAP login method: password fields vs. OAuth hints / Microsoft tenant.
    var auth = document.getElementById('imapAuthMethod');
    if (auth) {
        var applyAuth = function () {
            var v = auth.value;
            var show = {
                password: v === 'password',
                oauth: v !== 'password',
                microsoft: v === 'oauth_microsoft' || v === 'oauth_microsoft_app'
            };
            var nodes = document.querySelectorAll('[data-auth-show]');
            for (var i = 0; i < nodes.length; i++) {
                nodes[i].style.display = show[nodes[i].getAttribute('data-auth-show')] ? '' : 'none';
            }
        };
        auth.addEventListener('change', applyAuth);
        applyAuth();
    }

    var role = document.getElementById('userRole');
    var panel = document.getElementById('accountsPanel');
    if (role && panel) {
        var dim = function () { panel.style.opacity = role.value === 'ROLE_ADMIN' ? '0.5' : '1'; };
        role.addEventListener('change', dim);
        dim();
    }
})();
