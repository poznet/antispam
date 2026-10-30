/*
 * Background job page (/jobs/{id}): polls the JSON status endpoint while the
 * job is queued / running, updates the status label and progress bar, and
 * reloads the page when the job has finished so the server renders the
 * result. No inline script (CSP): wired through data-job-* attributes.
 */
(function () {
    var box = document.getElementById('jobStatus');
    if (!box || box.getAttribute('data-job-active') !== '1' || !window.fetch) {
        return;
    }
    var url = box.getAttribute('data-job-status-url');
    var delay = 2000;
    var classes = {queued: 'default', running: 'info', done: 'success', failed: 'danger', cancelled: 'warning'};

    function field(name) {
        return box.querySelector('[data-job-field="' + name + '"]');
    }

    function render(data) {
        var label = field('status_label');
        if (label) {
            label.textContent = data.status_label;
            label.className = 'label label-' + (classes[data.status] || 'default');
        }
        var progress = field('progress');
        if (progress && data.progress) {
            progress.textContent = data.progress;
        }
        var wrap = field('bar-wrap');
        var bar = field('bar');
        if (wrap && bar && data.percent !== null && data.percent !== undefined) {
            wrap.style.display = '';
            bar.style.width = data.percent + '%';
            bar.setAttribute('aria-valuenow', String(data.percent));
            var label = field('bar-label');
            if (label) {
                label.textContent = data.percent_label || (data.percent + '%');
            }
        }
    }

    function poll() {
        fetch(url, {credentials: 'same-origin', headers: {'Accept': 'application/json'}, cache: 'no-store'})
            .then(function (r) {
                if (!r.ok) {
                    throw new Error('HTTP ' + r.status);
                }
                return r.json();
            })
            .then(function (data) {
                render(data);
                if (data.finished) {
                    window.location.reload();
                    return;
                }
                delay = 2000;
                window.setTimeout(poll, delay);
            })
            .catch(function () {
                // Server busy / restarting / session expired: back off, keep trying.
                delay = Math.min(delay * 2, 30000);
                window.setTimeout(poll, delay);
            });
    }

    window.setTimeout(poll, delay);
})();
