#!/bin/sh
set -e

APP_DIR=/var/www/html

: "${SYMFONY_ENV:=prod}"
: "${DATABASE_HOST:=db}"
: "${DATABASE_PORT:=3306}"
: "${DATABASE_NAME:=antispam}"
: "${DATABASE_USER:=antispam}"
: "${DATABASE_PASSWORD:=antispam}"
: "${MAILER_TRANSPORT:=smtp}"
: "${MAILER_HOST:=127.0.0.1}"
: "${MAILER_USER:=}"
: "${MAILER_PASSWORD:=}"
: "${APP_SECRET:=ChangeMeInProductionPlease}"
: "${ADMIN_USER:=admin}"
: "${ADMIN_PASSWORD:=admin}"
: "${RUN_MIGRATIONS:=true}"

export SYMFONY_ENV

MAILER_USER_YAML="null"
if [ -n "$MAILER_USER" ]; then
    MAILER_USER_YAML="'${MAILER_USER}'"
fi

MAILER_PASSWORD_YAML="null"
if [ -n "$MAILER_PASSWORD" ]; then
    MAILER_PASSWORD_YAML="'${MAILER_PASSWORD}'"
fi

# Accept a pre-computed bcrypt hash (ADMIN_PASSWORD_HASH) or derive one from
# ADMIN_PASSWORD. "%" characters are escaped to "%%" because Symfony parameter
# resolution otherwise tries to expand them.
if [ -z "${ADMIN_PASSWORD_HASH:-}" ]; then
    ADMIN_PASSWORD_HASH=$(ADMIN_PASSWORD="$ADMIN_PASSWORD" php -r 'echo password_hash(getenv("ADMIN_PASSWORD"), PASSWORD_BCRYPT);')
fi
ADMIN_PASSWORD_HASH_ESCAPED=$(printf '%s' "$ADMIN_PASSWORD_HASH" | sed 's/%/%%/g')

# Generate parameters.yml from environment variables each startup
cat > "${APP_DIR}/app/config/parameters.yml" <<EOF
# Auto-generated from environment variables at container start.
parameters:
    database_host: '${DATABASE_HOST}'
    database_port: ${DATABASE_PORT}
    database_name: '${DATABASE_NAME}'
    database_user: '${DATABASE_USER}'
    database_password: '${DATABASE_PASSWORD}'

    mailer_transport: '${MAILER_TRANSPORT}'
    mailer_host: '${MAILER_HOST}'
    mailer_user: ${MAILER_USER_YAML}
    mailer_password: ${MAILER_PASSWORD_YAML}

    secret: '${APP_SECRET}'

    admin_user: '${ADMIN_USER}'
    admin_password_hash: '${ADMIN_PASSWORD_HASH_ESCAPED}'
EOF

# Wait for the database (max ~60s)
echo "[entrypoint] Waiting for MySQL at ${DATABASE_HOST}:${DATABASE_PORT}..."
i=0
until php -r "new PDO('mysql:host=${DATABASE_HOST};port=${DATABASE_PORT}', '${DATABASE_USER}', '${DATABASE_PASSWORD}');" >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge 30 ]; then
        echo "[entrypoint] WARN: database not reachable after $i attempts, continuing anyway"
        break
    fi
    sleep 2
done

# Make sure cache/log dirs are writable
mkdir -p "${APP_DIR}/app/cache" "${APP_DIR}/app/logs"
chown -R www-data:www-data "${APP_DIR}/app/cache" "${APP_DIR}/app/logs"

# Warmup cache and install bundle assets
php "${APP_DIR}/bin/console" cache:clear  --env="${SYMFONY_ENV}" --no-debug || true
php "${APP_DIR}/bin/console" cache:warmup --env="${SYMFONY_ENV}" --no-debug || true
php "${APP_DIR}/bin/console" assets:install "${APP_DIR}/web" --symlink --relative --env="${SYMFONY_ENV}" || true

# Create schema on first boot / keep it in sync
if [ "${RUN_MIGRATIONS}" = "true" ]; then
    php "${APP_DIR}/bin/console" doctrine:database:create --if-not-exists --env="${SYMFONY_ENV}" || true
    php "${APP_DIR}/bin/console" doctrine:schema:update --force --env="${SYMFONY_ENV}" || true
fi

chown -R www-data:www-data "${APP_DIR}/app/cache" "${APP_DIR}/app/logs"

# Warn loudly if the operator left the defaults in place
if [ "${APP_SECRET}" = "ChangeMeInProductionPlease" ]; then
    echo "[entrypoint] WARNING: APP_SECRET is using the default value - set a strong random secret!"
fi
if [ "${ADMIN_PASSWORD}" = "admin" ]; then
    echo "[entrypoint] WARNING: ADMIN_PASSWORD is set to 'admin' - change it before exposing the app!"
fi

exec "$@"
