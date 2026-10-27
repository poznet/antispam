# Landing page – antispam.pancernapanda.pl

Static marketing page for **Antispam Pancernapanda** (Pancerna Panda brand). Plain HTML/CSS/JS,
no build step and no dependency on the Symfony app.

```
landing/
  index.html            single-page site (PL)
  assets/css/style.css  brand theme: Deep Navy #060735, Royal Blue #005bba, Cyan #1fd7fd,
                        Montserrat (headlines) + Open Sans (body)
  assets/js/main.js     sticky header, mobile menu, scroll reveal, score meter demo
  assets/img/           shield icon, full logo, og-image.png (1200x630)
  favicon.ico, apple-touch-icon.png, robots.txt, sitemap.xml
```

## Deploy

Serve the `landing/` directory as a static document root (nginx, Apache, Coolify "Static" app).

The page links to the panel at `/login` and to the Thunderbird plugin at `/plugin/download`
(same host). If the panel lives on a different host, replace those links in `index.html`.

## Preview locally

```bash
cd landing && php -S localhost:8080
```
