# Upgrade do Symfony 4.4 LTS

## Przegląd zmian

Aplikacja Antispam została zaktualizowana z **Symfony 2.8** do **Symfony 4.4 LTS**.

### Wymagania systemowe

#### Przed aktualizacją (Symfony 2.8)
- PHP >= 5.3.9
- MySQL 5.x

#### Po aktualizacji (Symfony 4.4)
- **PHP >= 7.1.3** (zalecane: PHP 7.2, 7.3 lub 7.4)
- MySQL 5.7+ / MariaDB 10.2+
- ext-iconv

## Główne zmiany

### 1. Zaktualizowane zależności

#### Framework
- `symfony/symfony`: `2.8.*` → `4.4.*`
- `doctrine/orm`: `^2.4.8` → `^2.6`
- `doctrine/doctrine-bundle`: `~1.4` → `^1.12|^2.0`

#### Bundle
- `symfony/swiftmailer-bundle`: `~2.3` → `^3.4`
- `symfony/monolog-bundle`: `~2.4` → `^3.5`
- `sensio/framework-extra-bundle`: `^3.0.2` → `^5.5`
- `ddeboer/imap`: `^0.5.2` → `^1.0` (breaking changes - sprawdź dokumentację)

#### Usunięte bundle
- ❌ `symfony/assetic-bundle` - nie jest już wspierane w Symfony 4.x
- ❌ `sensio/distribution-bundle` - zastąpione przez Symfony Flex
- ❌ `sensio/generator-bundle` - zastąpione przez `symfony/maker-bundle`

#### Nowe bundle
- ✅ `symfony/asset` - zarządzanie assetami
- ✅ `symfony/dotenv` - zarządzanie zmiennymi środowiskowymi
- ✅ `symfony/maker-bundle` - generator kodu (dev)

### 2. Zmiany w kodzie

#### Komendy CLI

**Przed (Symfony 2.8):**
```php
use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;

class AntispamGoCommand extends ContainerAwareCommand
{
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $service = $this->getContainer()->get('service_name');
        // ...
    }
}
```

**Po (Symfony 4.4):**
```php
use Symfony\Component\Console\Command\Command;

class AntispamGoCommand extends Command
{
    protected static $defaultName = 'antispam:go';

    private $service;

    public function __construct(ServiceInterface $service)
    {
        $this->service = $service;
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        // ...
        return Command::SUCCESS; // lub Command::FAILURE
    }
}
```

**Kluczowe zmiany:**
- Dependency Injection zamiast Service Locator
- Metoda `execute()` zwraca `int` (0 = sukces, >0 = błąd)
- Statyczna właściwość `$defaultName` do definiowania nazwy komendy
- Używanie `Command::SUCCESS` i `Command::FAILURE`

#### Event Dispatcher

**Przed:**
```php
$dispatcher->dispatch('event.name', $event);
```

**Po:**
```php
$dispatcher->dispatch($event, 'event.name');
```

Kolejność argumentów została odwrócona w Symfony 4.4.

#### AppKernel.php

- Używanie składni array `[]` zamiast `array()`
- Usunięto AsseticBundle, SensioDistributionBundle, SensioGeneratorBundle
- Dodano MakerBundle (dev)

### 3. Zmiany w konfiguracji

#### config.yml

**Usunięto:**
```yaml
framework:
    templating:
        engines: ['twig']

assetic:
    debug: '%kernel.debug%'
    use_controller: '%kernel.debug%'
    filters:
        cssrewrite: ~
```

**Dodano:**
```yaml
framework:
    router:
        utf8: true
    session:
        cookie_secure: auto
        cookie_samesite: lax
    php_errors:
        log: true
```

#### services.yml

Dodano konfigurację dla komend z dependency injection:
```yaml
services:
    _defaults:
        autowire: false
        autoconfigure: false
        public: false

    AntispamBundle\Command\AntispamGoCommand:
        arguments:
            - "@antispam.inbox"
            - "@event_dispatcher"
            - "@configuration"
        tags: ['console.command']
```

### 4. Zmiany w Travis CI

**Przed:**
```yaml
php:
  - '5.5'

before_script:
  - php app/console doctrine:database:create --env=test
```

**Po:**
```yaml
php:
  - '7.2'
  - '7.3'
  - '7.4'

before_script:
  - php bin/console doctrine:database:create --env=test
```

- Zmiana `app/console` → `bin/console`
- Testy na PHP 7.2, 7.3, 7.4

## Instrukcje aktualizacji

### 1. Wymagania przed aktualizacją

```bash
# Sprawdź wersję PHP
php -v

# Powinno być >= 7.1.3, zalecane 7.2+
```

### 2. Aktualizacja zależności

```bash
# Usuń vendor i cache
rm -rf vendor/ app/cache/* app/logs/*

# Zainstaluj nowe zależności
composer install

# Może być konieczne:
composer update
```

### 3. Aktualizacja bazy danych

```bash
# Sprawdź zmiany w schemacie
php bin/console doctrine:schema:update --dump-sql

# Wykonaj aktualizację (jeśli potrzebna)
php bin/console doctrine:schema:update --force
```

### 4. Czyszczenie cache

```bash
php bin/console cache:clear --env=prod
php bin/console cache:clear --env=dev
```

### 5. Sprawdzenie aplikacji

```bash
# Sprawdź konfigurację
php bin/console antispam:check

# Uruchom testy
./bin/phpunit -c app
```

## Znane problemy i rozwiązania

### 1. ddeboer/imap ^1.0

Biblioteka `ddeboer/imap` została zaktualizowana z `^0.5.2` do `^1.0`. To **breaking change**.

**Możliwe problemy:**
- Zmienione API metod IMAP
- Inne nazwy klas/metod

**Rozwiązanie:**
Sprawdź [dokumentację ddeboer/imap](https://github.com/ddeboer/imap) i dostosuj kod jeśli występują błędy.

### 2. Brak AsseticBundle

AsseticBundle nie jest już wspierane w Symfony 4.x.

**Rozwiązania:**
1. Używaj Webpack Encore (zalecane dla większych projektów)
2. Zarządzaj assetami ręcznie przez `public/` directory
3. Używaj CDN dla bibliotek JS/CSS

### 3. Przestarzałe wywołania funkcji

Jeśli widzisz błędy typu:
```
The "templating" service is deprecated
```

Zamień na Twig:
```php
// Przed
$this->render('template.html.twig')

// Po
return $this->render('template.html.twig')
```

## Kompatybilność wsteczna

Większość kodu pozostaje kompatybilna, ale należy zwrócić uwagę na:

1. **Dependency Injection** - nie używaj `$this->getContainer()` w komendach
2. **Event Dispatcher** - odwrócona kolejność argumentów
3. **Zwracane wartości** - komendy muszą zwracać `int`
4. **Assety** - zarządzanie bez AsseticBundle

## Dodatkowe zasoby

- [Symfony 2.8 → 3.0 Upgrade Guide](https://github.com/symfony/symfony/blob/3.4/UPGRADE-3.0.md)
- [Symfony 3.4 → 4.0 Upgrade Guide](https://github.com/symfony/symfony/blob/4.4/UPGRADE-4.0.md)
- [Symfony 4.4 Documentation](https://symfony.com/doc/4.4/index.html)

## Wsparcie

W razie problemów:
1. Sprawdź logi: `app/logs/dev.log` lub `app/logs/prod.log`
2. Uruchom diagnostykę: `php bin/console debug:container`
3. Sprawdź routingi: `php bin/console debug:router`

---

# Upgrade do Symfony 5.4 LTS

## Przegląd zmian

Aplikacja została dodatkowo zaktualizowana z **Symfony 4.4 LTS** do **Symfony 5.4 LTS**.

### Wymagania systemowe

#### Po aktualizacji (Symfony 5.4)
- **PHP >= 7.2.5** (zalecane: PHP 7.4, 8.0 lub 8.1)
- **MySQL 5.7+** / MariaDB 10.2+
- **ext-iconv**
- **ext-ctype**

## Główne zmiany w Symfony 5.4

### 1. Zaktualizowane zależności

#### Framework
- `symfony/symfony`: `4.4.*` → `5.4.*`
- `doctrine/orm`: `^2.6` → `^2.10`
- `doctrine/doctrine-bundle`: `^1.12|^2.0` → `^2.5`

#### Bundle
- `sensio/framework-extra-bundle`: `^5.5` → `^6.2`
- `ddeboer/imap`: `^1.0` → `^1.13`
- `symfony/monolog-bundle`: `^3.5` → `^3.7`

#### Nowe wymagania
- ✅ `symfony/runtime` - nowy komponent runtime
- ✅ `ext-ctype` - rozszerzenie PHP

### 2. Rozwiązane problemy z migracji 4.4

#### ddeboer/imap API

**Zaktualizowano ConnectionService:**

```php
// Stara składnia (ddeboer/imap ^0.5)
$server = new Server($host, $port, $flags);
$connection = $server->authenticate($user, $pass);

// Nowa składnia (ddeboer/imap ^1.0+)
$serverFactory = new ServerFactory();
$server = $serverFactory->create($host, $port, $flags);
$connection = $server->authenticate($user, $pass);
```

#### Zarządzanie assetami

**Usunięto Assetic, zastąpiono CDN:**

```twig
{# Stara składnia z Assetic #}
{% javascripts 'assets/jquery/dist/jquery.min.js' %}
    <script src="{{ asset_url }}"></script>
{% endjavascripts %}

{# Nowa składnia - CDN #}
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
```

### 3. Zmiany w konfiguracji

#### config.yml - Framework

**Usunięto przestarzałe opcje:**
```yaml
framework:
    # USUNIĘTO:
    # strict_requirements: ~
    # trusted_hosts: ~
    # fragments: ~
```

**Dodano nowe opcje Symfony 5:**
```yaml
framework:
    session:
        storage_factory_id: session.storage.factory.native
    handle_all_throwables: true
```

#### Doctrine - Lepsze wsparcie UTF-8

**Zmiana z UTF8 na utf8mb4:**
```yaml
doctrine:
    dbal:
        charset: utf8mb4
        default_table_options:
            charset: utf8mb4
            collate: utf8mb4_unicode_ci
```

### 4. Zmiany w Travis CI

```yaml
php:
  - '7.2'
  - '7.3'
  - '7.4'
  - '8.0'
  - '8.1'
```

Aplikacja jest teraz testowana na PHP 7.2-8.1.

## Instrukcje aktualizacji do Symfony 5.4

### 1. Sprawdź wersję PHP

```bash
php -v
# Powinno być >= 7.2.5, zalecane 7.4 lub 8.0+
```

### 2. Aktualizacja zależności

```bash
# Usuń vendor i cache
rm -rf vendor/ app/cache/* app/logs/*

# Zainstaluj nowe zależności
composer install

# Jeśli wystąpią problemy:
composer update
```

### 3. Wyczyść cache

```bash
php bin/console cache:clear
php bin/console cache:warmup
```

### 4. Sprawdź bazę danych

```bash
php bin/console doctrine:schema:update --dump-sql
# Jeśli trzeba:
php bin/console doctrine:schema:update --force
```

## Co dalej?

Symfony 5.4 LTS jest wspierane do **listopada 2026**, co daje:
- ✅ 5 lat wsparcia bezpieczeństwa
- ✅ Stabilną platformę na produkcję
- ✅ Łatwą ścieżkę migracji do Symfony 6.x w przyszłości

## Migracja do Symfony 6.x (opcjonalnie)

Jeśli chcesz migrować do Symfony 6.x w przyszłości:
- Wymaga PHP >= 8.0.2
- Wymiana SwiftMailer na Symfony Mailer
- Większość kodu pozostaje kompatybilna dzięki Symfony 5.4 LTS

## Dodatkowe zasoby

- [Symfony 4.4 → 5.0 Upgrade Guide](https://github.com/symfony/symfony/blob/5.4/UPGRADE-5.0.md)
- [Symfony 5.4 Documentation](https://symfony.com/doc/5.4/index.html)
- [ddeboer/imap Documentation](https://github.com/ddeboer/imap)
