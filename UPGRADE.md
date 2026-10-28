# Upgrade: Symfony 4.4 → Symfony 7.4 LTS (PHP 8.2)

Aplikacja działa teraz na **Symfony 7.4 LTS** (poprawki błędów do 11/2028,
bezpieczeństwa do 11/2029) i wymaga **PHP 8.2 lub 8.3** (PHP 8.4 nie ma już
`ext-imap` w rdzeniu).

## Zależności

| Było | Jest |
| --- | --- |
| `symfony/symfony` 4.4 (cały framework) | pojedyncze komponenty `symfony/*` 7.4 |
| `doctrine/orm` 2.x, adnotacje | `doctrine/orm` 3.x + `doctrine/dbal` 4.x, atrybuty PHP 8 |
| `symfony/swiftmailer-bundle` (porzucony) | `symfony/mailer` |
| `sensio/framework-extra-bundle` (porzucony) | atrybuty `#[Route]` / `#[Template]` z Symfony |
| `poznet/configbundle` (dev-master, Symfony 2) | `AntispamBundle\Services\ConfigService` + encja `Config` w aplikacji (ta sama tabela `config`, ten sam format danych) |
| `incenteev/composer-parameter-handler`, `parameters.yml` | zmienne środowiskowe (`.env`, `.env.local`) |
| `symfony/maker-bundle`, `bower.json`, `.travis.yml`, `app/check.php`, `SymfonyRequirements.php` | usunięte |
| `symfony/phpunit-bridge` | `phpunit/phpunit` 11 |
| `ddeboer/imap` ^1.0 | `ddeboer/imap` ^1.19 (ta sama gałąź 1.x) |

## Struktura katalogów

| Było | Jest |
| --- | --- |
| `app/AppKernel.php`, `app/autoload.php` | `src/Kernel.php` (MicroKernel) |
| `app/config/*.yml` | `config/packages/*.yaml`, `config/routes.yaml`, `config/services.yaml` |
| `src/AntispamBundle/Resources/config/services*.yml` | `config/services.yaml` (autowiring, jawne priorytety listenerów) |
| `app/console` | `bin/console` |
| `web/` (`app.php`, `app_dev.php`) | `public/` (`index.php`) |
| `app/cache`, `app/logs` | `var/cache`, `var/log` |
| `app/Data/checked` | `var/data/checked` |

## Konfiguracja (`parameters.yml` → zmienne środowiskowe)

| `parameters.yml` | Zmienna |
| --- | --- |
| `secret` | `APP_SECRET` |
| `database_host` / `_port` / `_name` / `_user` / `_password` | `DATABASE_HOST` / `_PORT` / `_NAME` / `_USER` / `_PASSWORD` |
| — | `DATABASE_SERVER_VERSION` (np. `10.6.0-MariaDB`, `8.0.36`) |
| `mailer_transport` / `_host` / `_user` / `_password` | `MAILER_DSN`, np. `smtp://user:pass@smtp.example.com:587` |
| `admin_user` / `admin_password_hash` | `ADMIN_USER` / `ADMIN_PASSWORD_HASH` |
| `SYMFONY_ENV` | `APP_ENV` |

Domyślne wartości są w `.env` (w repozytorium); lokalne nadpisania w
`.env.local` (poza repozytorium). Hash hasła admina:
`php bin/console security:hash-password`.

W Dockerze nic nie trzeba zmieniać ręcznie: entrypoint nadal przyjmuje
`ADMIN_PASSWORD`, honoruje stare `SYMFONY_ENV` i składa `MAILER_DSN` ze starych
`MAILER_HOST` / `MAILER_USER` / `MAILER_PASSWORD`, jeśli `MAILER_DSN` nie jest
ustawione.

## Kroki aktualizacji (bez Dockera)

```bash
# 1. PHP 8.2/8.3 z rozszerzeniami imap, pdo_mysql, intl, zip, curl
php -v

# 2. Przenieś ustawienia z app/config/parameters.yml do .env.local (tabela wyżej)

# 3. Zależności (czyści cache i publikuje assety do public/bundles)
composer install --no-dev --optimize-autoloader

# 4. Schemat bazy (Doctrine Migrations, docs/migrations.md) - najpierw podgląd
php bin/console antispam:db:upgrade --dry-run
php bin/console antispam:db:upgrade

# 5. Web serwer: document root -> public/
# 6. Cron: ścieżki bin/console bez zmian (php bin/console antispam:...)
```

Opcjonalnie przenieś znaczniki sprawdzonych wiadomości IMAP, żeby nie były
skanowane ponownie: `mv app/Data/checked var/data/checked`.

## Docker / Coolify

- Obraz: `php:8.2-apache-bookworm`, document root `public/`.
- Wolumeny: `app_cache` zastąpiony przez `app_data` (`var/data`), `app_logs`
  wskazuje na `var/log`. Stare wolumeny można usunąć po wdrożeniu.

## Zmiany w kodzie

- Kontrolery dziedziczą po `AbstractController`, serwisy są wstrzykiwane w
  konstruktorze (zamiast `$this->get('...')`); stare identyfikatory serwisów
  (`antispam.inbox`, `configuration`, …) zastąpiły nazwy klas.
- Komendy używają `#[AsCommand]`.
- `MessageEvent` ma jawne `addReasons()` / `getReasons()` (PHP 8.2 nie pozwala
  już na dynamiczne właściwości).
- `ConnectionService` łączy się z IMAP dopiero przy pierwszym użyciu.
- Eksport reguł dla agenta jest w jednym miejscu: `AgentRulesExporter`.

## Naprawione przy okazji błędy

- „Zeruj liczniki” nic nie robiło (listenery nie były zarejestrowane) - teraz
  zeruje liczniki wszystkich czterech list.
- Wiadomości przeniesione do SPAM / kwarantanny / z powrotem do INBOX zostawały
  w folderze źródłowym z flagą `\Deleted` (brak `expunge`) i były przetwarzane
  ponownie przy każdym `antispam:go`.
- Strony Spambox / Kwarantanna kończyły się błędem 500 przy niepustym folderze
  (nadawca jako obiekt `EmailAddress`).
- Każda wiadomość IMAP dostawała +2 pkt `missing_message_id` (zły klucz
  nagłówka).
- `antispam:check` przy błędnym haśle IMAP kończył się wyjątkiem zamiast
  komunikatem.
