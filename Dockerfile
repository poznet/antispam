FROM php:7.4-apache-bullseye

# System dependencies required for PHP extensions (imap, iconv, zip) and composer
RUN apt-get update && apt-get install -y --no-install-recommends \
        libc-client-dev \
        libkrb5-dev \
        libicu-dev \
        libzip-dev \
        libssl-dev \
        libxml2-dev \
        zlib1g-dev \
        default-mysql-client \
        unzip \
        git \
        ssh \
    && rm -rf /var/lib/apt/lists/*

# PHP extensions needed by Antispam (IMAP mode, MySQL, iconv, etc.)
RUN docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
    && docker-php-ext-install -j"$(nproc)" \
        pdo_mysql \
        iconv \
        imap \
        intl \
        zip \
        opcache

# Production-ready PHP config
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php.ini /usr/local/etc/php/conf.d/zz-antispam.ini

# Apache modules + document root pointed at Symfony's web/ folder
ENV APACHE_DOCUMENT_ROOT=/var/www/html/web
RUN a2enmod rewrite headers \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}/!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1 \
    COMPOSER_NO_INTERACTION=1 \
    SYMFONY_ENV=prod

WORKDIR /var/www/html

# Install PHP deps first (better layer caching); skip scripts because they
# require parameters.yml which only exists at runtime.
COPY composer.json composer.lock* ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

# Copy the rest of the application
COPY . .

# Finalize autoload and asset install now that the source is present
RUN composer dump-autoload --no-dev --optimize --classmap-authoritative \
    && mkdir -p app/cache app/logs \
    && chown -R www-data:www-data app/cache app/logs

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["apache2-foreground"]
