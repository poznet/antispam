/*
 * Account form: clickable SSL/TLS options, live c-client flag preview and the
 * connection / certificate check (AccountController::imapCheckAction).
 * Mirrors AntispamBundle\Services\ImapFlags::build().
 */
(function () {
    var box = document.getElementById('imapSecurity');
    if (!box) { return; }
    var form = box.closest('form');
    var host = document.getElementById('imapHost');
    var port = document.getElementById('imapPort');
    var custom = document.getElementById('imapFlagsCustom');
    var customInput = document.getElementById('imapFlags');
    var preview = document.getElementById('imapMailboxPreview');
    var certGroup = document.getElementById('imapCertGroup');
    var out = document.getElementById('imapCheckResult');
    var defaultPorts = ['993', '143', ''];

    function checked(name) {
        var el = form.querySelector('input[name="account[imap_tls][' + name + ']"]:checked');
        return el ? el.value : null;
    }

    function buildFlags() {
        if (custom.checked) { return customInput.value.trim() || '/imap/ssl'; }
        var enc = checked('encryption') || 'ssl';
        var flags = '/imap' + ({ssl: '/ssl', starttls: '/tls', none: '/notls'}[enc] || '');
        if (enc !== 'none' && checked('validate_cert') === '0') { flags += '/novalidate-cert'; }
        ['secure', 'norsh', 'debug'].forEach(function (k) {
            if (checked(k)) { flags += '/' + k; }
        });
        return flags;
    }

    function refresh() {
        Array.prototype.forEach.call(box.querySelectorAll('.pp-choice'), function (card) {
            card.classList.toggle('is-active', card.querySelector('input').checked);
        });
        var noTls = checked('encryption') === 'none';
        certGroup.classList.toggle('is-disabled', noTls || custom.checked);
        box.querySelector('.pp-choice-grid').classList.toggle('is-disabled', custom.checked);
        document.getElementById('imapFlagsCustomGroup').style.display = custom.checked ? '' : 'none';
        if (custom.checked && !customInput.dataset.touched) {
            customInput.value = buildFlagsFromOptions();
        }
        preview.textContent = '{' + (host.value.trim() || 'host') + ':' + (port.value || '?') + buildFlags() + '}';
    }

    function buildFlagsFromOptions() {
        var was = custom.checked;
        custom.checked = false;
        var f = buildFlags();
        custom.checked = was;
        return f;
    }

    box.addEventListener('change', function (e) {
        if (e.target.name === 'account[imap_tls][encryption]' && defaultPorts.indexOf(port.value) !== -1) {
            port.value = e.target.getAttribute('data-port');
        }
        refresh();
    });
    customInput.addEventListener('input', function () { customInput.dataset.touched = '1'; refresh(); });
    host.addEventListener('input', refresh);
    port.addEventListener('input', refresh);
    customInput.dataset.touched = custom.checked ? '1' : '';
    refresh();

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
        });
    }

    var icons = {ok: 'ok-sign text-success', warning: 'exclamation-sign text-warning', error: 'remove-sign text-danger'};

    function renderSteps(steps) {
        return '<ul class="pp-imap-steps">' + steps.map(function (s) {
            return '<li><span class="glyphicon glyphicon-' + (icons[s.status] || icons.warning) + '"></span> '
                + '<span><strong>' + esc(s.label) + '</strong>'
                + (s.detail ? '<br><span class="text-muted">' + esc(s.detail) + '</span>' : '') + '</span></li>';
        }).join('') + '</ul>';
    }

    function renderCert(c, tls) {
        if (!c) { return ''; }
        var rows = [
            ['Podmiot (CN)', c.subject_cn],
            ['Nazwy (SAN)', (c.names || []).join(', ')],
            ['Wystawca', c.issuer],
            ['Ważny', (c.valid_from || '?') + ' → ' + (c.valid_to || '?') + (c.days_left != null ? ' (' + c.days_left + ' dni)' : '')],
            ['Zgodność z hostem', c.hostname_match ? 'tak' : 'NIE'],
            ['Zaufany łańcuch', c.verified ? 'tak' : 'NIE' + (c.verify_error ? ' – ' + c.verify_error : '')],
            ['Samopodpisany', c.self_signed ? 'tak' : 'nie'],
            ['TLS', tls ? [tls.protocol, tls.cipher, tls.bits ? tls.bits + ' bit' : ''].filter(Boolean).join(', ') : ''],
            ['SHA-256', c.fingerprint]
        ];
        return '<table class="table table-condensed pp-imap-cert"><tbody>' + rows.map(function (r) {
            return '<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>';
        }).join('') + '</tbody></table>';
    }

    function render(r) {
        var html = '<div class="alert alert-' + (r.ok ? 'success' : 'danger') + '">'
            + (r.ok ? 'Połączenie działa z wybranymi ustawieniami.' : 'Połączenie z wybranymi ustawieniami nie działa.')
            + (r.flags ? ' <code>' + esc(r.flags) + '</code>' : '') + '</div>';
        html += renderSteps(r.steps || []);
        html += renderCert(r.certificate, r.tls);
        if (r.capabilities && r.capabilities.length) {
            html += '<p class="text-muted small">Możliwości serwera: ' + r.capabilities.map(function (c) {
                return '<span class="label label-default">' + esc(c) + '</span>';
            }).join(' ') + '</p>';
        }
        return html;
    }

    function setChoice(name, value) {
        var el = form.querySelector('input[name="account[imap_tls][' + name + ']"][value="' + value + '"]');
        if (el) { el.checked = true; }
    }

    function renderDetect(d) {
        var labels = {ssl: 'SSL/TLS', starttls: 'STARTTLS'};
        var html = '';
        if (d.recommended) {
            html += '<div class="alert alert-success">Zastosowano: <strong>' + labels[d.recommended.encryption]
                + '</strong>, port ' + d.recommended.port + ', '
                + (d.recommended.validate_cert ? 'certyfikat zaufany (weryfikacja włączona).' : 'certyfikat niezaufany – weryfikacja wyłączona.')
                + ' Sprawdź połączenie, żeby potwierdzić logowanie.</div>';
        } else {
            html += '<div class="alert alert-danger">Nie znaleziono działającego połączenia na portach 993 ani 143.</div>';
        }
        (d.results || []).forEach(function (r) {
            html += '<h5>' + labels[r.encryption] + ' – port ' + r.port + ' '
                + (r.ok ? '<span class="label label-success">działa</span>' : '<span class="label label-danger">nie działa</span>') + '</h5>'
                + renderSteps(r.probe.steps || []);
        });
        return html;
    }

    function run(mode, btn) {
        if (!host.value.trim()) {
            out.innerHTML = '<div class="alert alert-warning">Podaj host IMAP.</div>';
            host.focus();
            return;
        }
        var data = new FormData(form);
        if (mode) { data.append('mode', mode); }
        var buttons = box.querySelectorAll('.pp-imap-actions .btn');
        Array.prototype.forEach.call(buttons, function (b) { b.disabled = true; });
        btn.classList.add('is-loading');
        out.innerHTML = '<p class="text-muted"><span class="glyphicon glyphicon-refresh"></span> Łączenie z serwerem…</p>';
        fetch(box.getAttribute('data-check-url'), {method: 'POST', body: data, credentials: 'same-origin', headers: {'Accept': 'application/json'}})
            .then(function (res) {
                if (!res.ok) { throw new Error('HTTP ' + res.status); }
                return res.json();
            })
            .then(function (r) {
                if (mode === 'detect') {
                    if (r.recommended) {
                        custom.checked = false;
                        setChoice('encryption', r.recommended.encryption);
                        setChoice('validate_cert', r.recommended.validate_cert ? '1' : '0');
                        port.value = r.recommended.port;
                        refresh();
                    }
                    out.innerHTML = renderDetect(r);
                } else {
                    out.innerHTML = render(r);
                }
            })
            .catch(function (e) {
                out.innerHTML = '<div class="alert alert-danger">Test nie powiódł się: ' + esc(e.message) + '</div>';
            })
            .then(function () {
                Array.prototype.forEach.call(buttons, function (b) { b.disabled = false; });
                btn.classList.remove('is-loading');
            });
    }

    document.getElementById('imapCheckBtn').addEventListener('click', function () { run(null, this); });
    document.getElementById('imapDetectBtn').addEventListener('click', function () { run('detect', this); });
})();
