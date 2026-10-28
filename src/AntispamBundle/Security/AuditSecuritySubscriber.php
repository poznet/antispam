<?php

namespace AntispamBundle\Security;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Services\AuditLogger;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Panel logins (form_login of the `main` firewall) and logouts go to the
 * audit log. The submitted password is never read; a failed login records the
 * login that was typed (shortened) and the reason class only.
 */
class AuditSecuritySubscriber implements EventSubscriberInterface
{
    public function __construct(private AuditLogger $audit)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
            LoginFailureEvent::class => 'onLoginFailure',
            LogoutEvent::class => 'onLogout',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        [$actor, $type, $role] = self::describe($event->getUser());
        $this->audit->log('auth.login', targetType: 'user', label: $actor, details: ['firewall' => $event->getFirewallName()],
            actor: $actor, actorType: $type, role: $role);
    }

    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $login = '';
        $passport = $event->getPassport();
        if ($passport && $passport->hasBadge(UserBadge::class)) {
            $login = $passport->getBadge(UserBadge::class)->getUserIdentifier();
        } elseif ($event->getRequest()->request->has('_username')) {
            $login = (string)$event->getRequest()->request->get('_username');
        }
        // Keep only printable characters of what was typed.
        $login = mb_substr((string)preg_replace('/[\x00-\x1f\x7f]/', '', $login), 0, 180);
        $exception = $event->getException();
        $this->audit->log('auth.login_failed', targetType: 'user', label: $login !== '' ? $login : null, details: [
            'reason' => $exception instanceof TooManyLoginAttemptsAuthenticationException ? 'throttled' : (new \ReflectionClass($exception))->getShortName(),
        ], actor: $login !== '' ? $login : 'anonymous', actorType: AuditLog::ACTOR_ANONYMOUS);
    }

    public function onLogout(LogoutEvent $event): void
    {
        $user = $event->getToken()?->getUser();
        if (!$user instanceof UserInterface) {
            return;
        }
        [$actor, $type, $role] = self::describe($user);
        $this->audit->log('auth.logout', targetType: 'user', label: $actor, actor: $actor, actorType: $type, role: $role);
    }

    /** @return array{0: string, 1: string, 2: ?string} */
    private static function describe(UserInterface $user): array
    {
        if ($user instanceof User) {
            return [(string)$user->getUsername(), AuditLog::ACTOR_USER, (string)$user->getRole()];
        }
        return [$user->getUserIdentifier(), AuditLog::ACTOR_ENV_ADMIN, 'ROLE_ADMIN'];
    }
}
