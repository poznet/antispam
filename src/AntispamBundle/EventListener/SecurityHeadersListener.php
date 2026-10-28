<?php

namespace AntispamBundle\EventListener;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Security headers for every response of the application (see
 * docs/deployment.md, "Security headers"). Headers a controller already set
 * (e.g. the stricter Referrer-Policy of the /q/ pages or the sandbox CSP of
 * the .eml export) are left untouched.
 *
 * Content-Security-Policy per route:
 *  - /plugin/outlook/*: none, and no frame blocking - the task pane is framed
 *    by Outlook (web, desktop webview, mobile) and loads office.js, which pulls
 *    further scripts and frames from Microsoft's CDN.
 *  - /q/*: strict - anonymous pages opened from the digest
 *    e-mail; only same-origin script files (theme-init.js), no inline JS.
 *  - everything else (panel, user area, home page, login, error pages):
 *    same-origin only. 'unsafe-inline' stays for scripts and styles because the
 *    shared layout, the home page, the error page and several forms still use
 *    inline <script> blocks, inline onclick handlers and style="" attributes.
 *    Remote images are blocked, which also covers the spam preview iframe
 *    (srcdoc inherits the policy of the panel page).
 */
#[AsEventListener(event: KernelEvents::RESPONSE, priority: -16)]
class SecurityHeadersListener
{
    public const POLICY_DEFAULT = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        . "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; "
        . "base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

    public const POLICY_DIGEST = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        . "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    public const HSTS = 'max-age=31536000';

    public function __construct(
        #[Autowire('%kernel.environment%')] private string $environment,
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        $response = $event->getResponse();

        foreach (self::headersFor($request, $response, $this->environment) as $name => $value) {
            if (!$response->headers->has($name)) {
                $response->headers->set($name, $value);
            }
        }
    }

    /**
     * @return array<string, string> header name => value
     */
    public static function headersFor(Request $request, Response $response, string $environment): array
    {
        $path = $request->getPathInfo();
        $headers = [
            'X-Content-Type-Options' => 'nosniff',
            'Referrer-Policy' => 'same-origin',
            'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), payment=()',
        ];

        // HSTS only in prod and only over https (behind a TLS proxy this needs
        // SYMFONY_TRUSTED_PROXIES + X-Forwarded-Proto, see docs/deployment.md).
        if ($environment === 'prod' && $request->isSecure()) {
            $headers['Strict-Transport-Security'] = self::HSTS;
        }

        if (self::isOutlookPath($path)) {
            return $headers;
        }

        $headers['X-Frame-Options'] = 'DENY';
        if (self::isHtml($response)) {
            $headers['Content-Security-Policy'] = str_starts_with($path, '/q/') ? self::POLICY_DIGEST : self::POLICY_DEFAULT;
        }

        return $headers;
    }

    public static function isOutlookPath(string $path): bool
    {
        return str_starts_with($path, '/plugin/outlook/');
    }

    private static function isHtml(Response $response): bool
    {
        $type = (string)$response->headers->get('Content-Type', '');

        // Twig responses get their text/html Content-Type only in prepare(),
        // after this listener - an empty type means HTML.
        return $type === '' || str_starts_with(strtolower($type), 'text/html');
    }
}
