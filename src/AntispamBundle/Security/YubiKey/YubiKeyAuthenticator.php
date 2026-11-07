<?php

namespace AntispamBundle\Security\YubiKey;

use AntispamBundle\Entity\YubiKey;
use AntispamBundle\Security\AdminUserProvider;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Passwordless login with a YubiKey: POST /login/yubikey with the OTP the
 * key typed (field `otp`, CSRF `yubikey_login`). The public ID of the OTP
 * finds the registered key and its user; the OTP is validated by the Yubico
 * server (YubiKeyService::check). Only when "Logowanie samym kluczem" is on
 * (yubikey.passwordless) and the API is configured.
 *
 * The hardware key replaces password + second factor: TwoFactorGuard marks
 * the session as "2FA passed" for this authenticator. Failures are throttled
 * per client IP (`yubikey_login` limiter) - login_throttling of the firewall
 * also applies (keyed by the owner's login).
 */
class YubiKeyAuthenticator extends AbstractAuthenticator
{
    use TargetPathTrait;

    public const ROUTE = 'login_yubikey';
    public const CSRF_ID = 'yubikey_login';

    public function __construct(
        private YubiKeyService $yubiKeys,
        private UrlGeneratorInterface $urls,
        #[Autowire(service: 'limiter.yubikey_login')] private RateLimiterFactoryInterface $limiter,
        private ?LoggerInterface $logger = null,
        #[Autowire(lazy: true)] private ?AdminUserProvider $envAdmins = null,
    ) {
        $this->logger ??= new NullLogger();
    }

    public function supports(Request $request): ?bool
    {
        return $request->isMethod('POST') && $request->attributes->get('_route') === self::ROUTE;
    }

    public function authenticate(Request $request): Passport
    {
        if (!$this->yubiKeys->isPasswordlessEnabled()) {
            throw new CustomUserMessageAuthenticationException('Logowanie samym kluczem YubiKey jest wyłączone.');
        }
        $limit = $this->limiter->create('yk-' . ($request->getClientIp() ?? 'unknown'))->consume(1);
        if (!$limit->isAccepted()) {
            $this->logger->warning('YubiKey login throttled', ['ip' => $request->getClientIp()]);
            throw new CustomUserMessageAuthenticationException('Zbyt wiele prób logowania kluczem. Spróbuj ponownie za kilkanaście minut.');
        }

        $otp = YubicoOtpClient::normalize((string)$request->request->get('otp'));
        if (!YubicoOtpClient::isOtp($otp)) {
            throw new CustomUserMessageAuthenticationException('To nie jest kod z klucza YubiKey - kliknij w pole i dotknij klucza.');
        }
        $key = $this->yubiKeys->findKeyForOtp($otp);
        if (!$key instanceof YubiKey) {
            $this->logger->notice('YubiKey login: unknown key {public_id}', ['public_id' => YubicoOtpClient::publicId($otp)]);
            throw new CustomUserMessageAuthenticationException('Ten klucz YubiKey nie jest zarejestrowany w panelu.');
        }
        $username = $key->getOwnerLogin();
        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $username);
        // Database user: the key's owner. Env admin key: only while ADMIN_USER
        // still has that login (AdminUserProvider throws otherwise).
        $loader = $key->getUser() !== null
            ? fn() => $key->getUser()
            : function (string $login) {
                if (!$this->envAdmins) {
                    throw new UserNotFoundException();
                }
                return $this->envAdmins->loadUserByIdentifier($login);
            };

        return new Passport(
            new UserBadge($username, $loader),
            new CustomCredentials(function (string $otp, UserInterface $user) use ($key) {
                $status = $this->yubiKeys->check($otp);
                if ($status !== YubicoOtpClient::STATUS_OK) {
                    $this->logger->notice('YubiKey login failed for {user}: {status}', ['user' => $user->getUserIdentifier(), 'status' => $status]);
                    throw new CustomUserMessageAuthenticationException(YubicoOtpClient::describe($status));
                }
                $this->yubiKeys->markUsed($key);
                return true;
            }, $otp),
            [new CsrfTokenBadge(self::CSRF_ID, (string)$request->request->get('_csrf_token')), new YubiKeyLoginBadge($key->getPublicId())],
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $this->limiter->create('yk-' . ($request->getClientIp() ?? 'unknown'))->reset();
        $target = $request->hasSession() ? $this->getTargetPath($request->getSession(), $firewallName) : null;
        return new RedirectResponse($target ?: $this->urls->generate('antispam_start'));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($request->hasSession()) {
            $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);
        }
        return new RedirectResponse($this->urls->generate('antispam_home') . '#logowanie');
    }
}
