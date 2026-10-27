#!/bin/sh
set -e

APP_DIR=/var/www/html

# SYMFONY_ENV is the pre-Symfony-7 name, still honoured.
: "${APP_ENV:=${SYMFONY_ENV:-prod}}"
: "${DATABASE_HOST:=db}"
: "${DATABASE_PORT:=3306}"
: "${DATABASE_NAME:=antispam}"
: "${DATABASE_USER:=antispam}"
: "${DATABASE_PASSWORD:=antispam}"
: "${DATABASE_SERVER_VERSION:=10.6.0-MariaDB}"
: "${APP_SECRET:=ChangeMeInProductionPlease}"
: "${ADMIN_USER:=admin}"
: "${RUN_MIGRATIONS:=true}"

# Accept a pre-computed hash (ADMIN_PASSWORD_HASH) or derive one from
# ADMIN_PASSWORD.
if [ -z "${ADMIN_PASSWORD_HASH:-}" ]; then
    : "${ADMIN_PASSWORD:=admin}"
    if [ "${ADMIN_PASSWORD}" = "admin" ]; then
        echo "[entrypoint] WARNING: ADMIN_PASSWORD is set to 'admin' - change it before exposing the app!"
    fi
    ADMIN_PASSWORD_HASH=$(ADMIN_PASSWORD="$ADMIN_PASSWORD" php -r 'echo password_hash(getenv("ADMIN_PASSWORD"), PASSWORD_BCRYPT);')
fi

# MAILER_DSN, or one built from the legacy MAILER_TRANSPORT/HOST/USER/PASSWORD
# variables (Swiftmailer era).
if [ -z "${MAILER_DSN:-}" ]; then
    MAILER_DSN=$(php -r '
        $host = (string)getenv("MAILER_HOST");
        $transport = (string)getenv("MAILER_TRANSPORT") ?: "smtp";
        if ($host === "" || $transport === "null") { echo "null://null"; exit; }
        $user = (string)getenv("MAILER_USER");
        $auth = $user === "" ? "" : rawurlencode($user) . ":" . rawurlencode((string)getenv("MAILER_PASSWORD")) . "@";
        echo "smtp://" . $auth . $host . (strpos($host, ":") === false ? ":25" : "");
    ')
fi

export APP_ENV APP_SECRET ADMIN_USER ADMIN_PASSWORD_HASH MAILER_DSN \
    DATABASE_HOST DATABASE_PORT DATABASE_NAME DATABASE_USER DATABASE_PASSWORD DATABASE_SERVER_VERSION

# Freeze the configuration into .env.local.php: Apache/mod_php does not expose
# the container environment to $_SERVER, and this also skips parsing .env on
# every request.
php -r '
    $vars = ["APP_ENV", "APP_SECRET", "ADMIN_USER", "ADMIN_PASSWORD_HASH", "MAILER_DSN",
        "DATABASE_HOST", "DATABASE_PORT", "DATABASE_NAME", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_SERVER_VERSION"];
    $env = ["APP_DEBUG" => getenv("APP_ENV") === "prod" ? "0" : "1"];
    foreach ($vars as $v) { $env[$v] = (string)getenv($v); }
    file_put_contents($argv[1], "<?php\n\n// Auto-generated from environment variables at container start.\nreturn " . var_export($env, true) . ";\n");
' "${APP_DIR}/.env.local.php"

# Wait for the database (max ~60s)
echo "[entrypoint] Waiting for MySQL at ${DATABASE_HOST}:${DATABASE_PORT}..."
i=0
until php -r 'new PDO("mysql:host=" . getenv("DATABASE_HOST") . ";port=" . getenv("DATABASE_PORT"), getenv("DATABASE_USER"), getenv("DATABASE_PASSWORD"));' >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge 30 ]; then
        echo "[entrypoint] WARN: database not reachable after $i attempts, continuing anyway"
        break
    fi
    sleep 2
done

mkdir -p "${APP_DIR}/var/cache" "${APP_DIR}/var/log" "${APP_DIR}/var/data"

# Rebuild the cache for the current configuration
php "${APP_DIR}/bin/console" cache:clear --no-debug || true

# Create schema on first boot / keep it in sync
if [ "${RUN_MIGRATIONS}" = "true" ]; then
    php "${APP_DIR}/bin/console" doctrine:database:create --if-not-exists || true
    php "${APP_DIR}/bin/console" doctrine:schema:update --force || true
fi

chown -R www-data:www-data "${APP_DIR}/var"

# Warn loudly if the operator left the default secret in place
if [ "${APP_SECRET}" = "ChangeMeInProductionPlease" ]; then
    echo "[entrypoint] WARNING: APP_SECRET is using the default value - set a strong random secret!"
fi

exec "$@"
