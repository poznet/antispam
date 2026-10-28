FROM php:8.2-apache-bookworm

# System dependencies required for PHP extensions (imap, intl, zip) and composer
RUN apt-get update && apt-get install -y --no-install-recommends \
        libc-client-dev \
        libkrb5-dev \
        libicu-dev \
        libzip-dev \
        default-mysql-client \
        unzip \
        git \
        ssh \
    && rm -rf /var/lib/apt/lists/*

# PHP extensions needed by Antispam (IMAP mode, MySQL, intl, zip for the Thunderbird .xpi)
RUN docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install -j"$(nproc)" \
        pdo_mysql \
        imap \
        intl \
        zip \
        opcache

# Production-ready PHP config
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-antispam.ini

# Apache modules + document root pointed at Symfony's public/ folder
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
COPY docker/apache-security.conf /etc/apache2/conf-available/zz-antispam-security.conf
RUN a2enmod rewrite headers \
    && a2enconf zz-antispam-security \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}/!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1 \
    APP_ENV=prod

WORKDIR /var/www/html

# Install PHP deps first (better layer caching); scripts need the app source.
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

# Copy the rest of the application
COPY . .

# Commit the image is built from (.git is dockerignored, so it must come in as a
# build arg). Coolify: compose passes GIT_COMMIT=${SOURCE_COMMIT}; see
# docs/deployment.md "Releasing". Declared this late so a new commit only
# invalidates the layers below. Read by AntispamBundle\AppVersion.
ARG GIT_COMMIT=unknown
RUN printf '%s\n' "${GIT_COMMIT}" > REVISION

# Finalize autoload and publish bundle assets now that the source is present
RUN composer dump-autoload --no-dev --optimize --classmap-authoritative \
    && composer run-script --no-dev post-install-cmd \
    && mkdir -p var/cache var/log var/data \
    && chown -R www-data:www-data var

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/scheduler.sh /usr/local/bin/scheduler.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/scheduler.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
