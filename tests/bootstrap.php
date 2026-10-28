<?php

use Symfony\Component\Dotenv\Dotenv;

require dirname(__DIR__) . '/vendor/autoload.php';

// Kernel tests (AccessControlTest...) need the .env defaults, e.g. DATABASE_HOST,
// to compile the container from a cold cache.
if (method_exists(Dotenv::class, 'bootEnv')) {
    (new Dotenv())->bootEnv(dirname(__DIR__) . '/.env');
}
