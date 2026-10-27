/* Antispam Pancernapanda - landing page interactions */
(function () {
    'use strict';
    document.documentElement.classList.remove('no-js');

    var header = document.querySelector('.site-header');
    var toggle = document.querySelector('.nav-toggle');

    function onScroll() {
        header.classList.toggle('scrolled', window.scrollY > 20);
    }
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    toggle.addEventListener('click', function () {
        var open = header.classList.toggle('open');
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        header.classList.add('scrolled');
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-links a, .nav-cta a'), function (a) {
        a.addEventListener('click', function () {
            header.classList.remove('open');
            toggle.setAttribute('aria-expanded', 'false');
        });
    });

    if (!('IntersectionObserver' in window)) {
        Array.prototype.forEach.call(document.querySelectorAll('.reveal'), function (el) { el.classList.add('in'); });
        return;
    }

    // Reveal sections on scroll
    var revealer = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
            if (e.isIntersecting) {
                e.target.classList.add('in');
                revealer.unobserve(e.target);
            }
        });
    }, { threshold: 0.12 });
    Array.prototype.forEach.call(document.querySelectorAll('.reveal'), function (el) { revealer.observe(el); });

    // Highlight the current section in the nav
    var links = {};
    Array.prototype.forEach.call(document.querySelectorAll('.nav-links a[href^="#"]'), function (a) {
        links[a.getAttribute('href').slice(1)] = a;
    });
    var spy = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
            var link = links[e.target.id];
            if (link && e.isIntersecting) {
                Object.keys(links).forEach(function (k) { links[k].classList.remove('active'); });
                link.classList.add('active');
            }
        });
    }, { rootMargin: '-45% 0px -50% 0px' });
    Object.keys(links).forEach(function (id) {
        var s = document.getElementById(id);
        if (s) spy.observe(s);
    });

    // Score meter demo: walk the pin through ham -> quarantine -> spam
    var pin = document.querySelector('.meter-pin span');
    if (pin) {
        var stops = [
            { score: 2, label: 'Wynik 2 · czysta' },
            { score: 7, label: 'Wynik 7 · kwarantanna' },
            { score: 14, label: 'Wynik 14 · SPAM' }
        ];
        var i = 0;
        var max = 16;
        var tick = function () {
            var s = stops[i % stops.length];
            pin.style.left = (s.score / max * 100) + '%';
            pin.textContent = s.label;
            i++;
        };
        var meterObs = new IntersectionObserver(function (entries) {
            if (entries[0].isIntersecting) {
                tick();
                setInterval(tick, 2600);
                meterObs.disconnect();
            }
        }, { threshold: 0.4 });
        meterObs.observe(pin.closest('.meter'));
    }
})();
