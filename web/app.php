<?php

use Symfony\Component\HttpFoundation\Request;

/**
 * @var Composer\Autoload\ClassLoader
 */
$loader = require __DIR__.'/../app/autoload.php';

// Behind a reverse proxy (Coolify / Traefik) trust its X-Forwarded-* headers,
// so Symfony sees the original https:// scheme and host.
// TRUSTED_PROXIES is a comma-separated list of IPs / CIDR ranges.
if ($trustedProxies = getenv('TRUSTED_PROXIES')) {
    Request::setTrustedProxies(explode(',', $trustedProxies), Request::HEADER_X_FORWARDED_ALL);
}

$kernel = new AppKernel('prod', false);
//$kernel = new AppCache($kernel);

// When using the HttpCache, you need to call the method in your front controller instead of relying on the configuration parameter
//Request::enableHttpMethodParameterOverride();
$request = Request::createFromGlobals();
$response = $kernel->handle($request);
$response->send();
$kernel->terminate($request, $response);
