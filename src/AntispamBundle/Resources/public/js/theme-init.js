/*
 * Applies the panel's light/dark choice (localStorage "pp-theme", set by the theme toggle in the panel)
 * on standalone pages (error page, /q/ quarantine links). Without a stored choice the page follows
 * prefers-color-scheme through its own CSS. Loaded synchronously in <head> to avoid a flash of the wrong theme.
 */
(function () {
    var t = null;
    try { t = localStorage.getItem('pp-theme'); } catch (e) {}
    if (t === 'light' || t === 'dark') { document.documentElement.setAttribute('data-theme', t); }
})();
