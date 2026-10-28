<?php

namespace AntispamBundle\Security\TwoFactor;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\AccessMapInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Second login step. form_login authenticates the password as before; then,
 * on every request of a logged-in user:
 *
 *   - 2FA on and not yet passed in this session -> only /2fa (code form) and
 *     /logout are reachable, everything else redirects to /2fa;
 *   - administrator without 2FA while "wymagaj 2FA dla administratorów" is on
 *     -> only the setup page /my/2fa (+ /2fa, /logout) is reachable.
 *
 * Runs after the firewall (priority 8), so the token is loaded and
 * access_control has already been applied. Public paths (PUBLIC_ACCESS in
 * access_control: home, /q/, /api/*, /health...) do not use the panel
 * identity and are left alone. The "passed" marker is dropped on every new
 * login, so a session can never carry it over to another authentication.
 */
class TwoFactorGuard implements EventSubscriberInterface
{
    public const ROUTE_VERIFY = 'antispam_2fa_verify';
    public const ROUTE_SETUP = 'antispam_my_2fa';

    /** Reachable while the code is pending. */
    private const PENDING_ROUTES = [self::ROUTE_VERIFY, 'logout'];
    /** Reachable while an enforced setup is pending. */
    private const SETUP_ROUTES = [self::ROUTE_SETUP, 'antispam_my_2fa_enable', self::ROUTE_VERIFY, 'logout'];

    public function __construct(
        private TokenStorageInterface $tokens,
        private TwoFactorService $twoFactor,
        private UrlGeneratorInterface $urls,
        #[Autowire(service: 'security.access_map')] private AccessMapInterface $accessMap,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onRequest', 4],
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $request = $event->getRequest();
        if ($request->hasSession()) {
            $this->twoFactor->clearPassed($request->getSession());
            $this->twoFactor->discardPendingSecret($request->getSession());
        }
    }

    public function onRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $request = $event->getRequest();
        $state = $this->state($request);
        if ($state === null) {
            return;
        }
        $route = (string)$request->attributes->get('_route');
        $allowed = $state === 'code' ? self::PENDING_ROUTES : self::SETUP_ROUTES;
        if (in_array($route, $allowed, true)) {
            return;
        }
        if ($state === 'setup' && $request->hasSession() && $request->getSession() instanceof FlashBagAwareSessionInterface) {
            $request->getSession()->getFlashBag()->set('warning', ['Administrator musi włączyć weryfikację dwuetapową (2FA), zanim skorzysta z panelu.']);
        }
        $event->setResponse(new RedirectResponse($this->urls->generate($state === 'code' ? self::ROUTE_VERIFY : self::ROUTE_SETUP)));
    }

    /**
     * What the current request still owes: 'code', 'setup' or null (nothing).
     */
    public function state(Request $request): ?string
    {
        // Public paths first: no need to load the (lazy) token for them.
        [$attributes] = $this->accessMap->getPatterns($request);
        if ($attributes === ['PUBLIC_ACCESS'] || !$request->hasSession()) {
            return null;
        }
        $user = $this->tokens->getToken()?->getUser();
        if (!$user instanceof UserInterface) {
            return null;
        }
        if ($this->twoFactor->isEnabled($user)) {
            return $this->twoFactor->isPassed($request->getSession(), $user) ? null : 'code';
        }
        return $this->twoFactor->needsSetup($user) ? 'setup' : null;
    }
}
