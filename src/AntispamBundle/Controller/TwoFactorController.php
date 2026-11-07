<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\User;
use AntispamBundle\Security\TwoFactor\QrCodeRenderer;
use AntispamBundle\Security\TwoFactor\TwoFactorGuard;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Security\YubiKey\YubicoOtpClient;
use AntispamBundle\Security\YubiKey\YubiKeyService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Two-factor authentication (TOTP) - the code step of the login (/2fa) and
 * the own 2FA settings (/my/2fa: set up with a QR code, backup codes,
 * disable). Both need a logged-in user (access_control ^/(my|start|2fa) ->
 * ROLE_USER); TwoFactorGuard keeps everything else closed until the code was
 * given. Every code check is rate limited (TwoFactorService::consumeAttempt)
 * and audited.
 */
class TwoFactorController extends AbstractController
{
    use AuditTrait;

    public function __construct(
        private TwoFactorService $twoFactor,
        private QrCodeRenderer $qr,
        private UserPasswordHasherInterface $hasher,
        private TwoFactorGuard $guard,
        private ?YubiKeyService $yubiKeys = null,
    ) {
    }

    /** Second login step: TOTP code or a backup code. */
    #[Route('/2fa', name: 'antispam_2fa_verify', methods: ['GET', 'POST'])]
    public function verifyAction(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user || $this->guard->state($request) !== 'code') {
            return $this->redirectToRoute('antispam_start');
        }

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('two_factor_verify', (string)$request->request->get('_token'))) {
                $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            } elseif (!$this->twoFactor->consumeAttempt($user)) {
                $this->failed('login', 'throttled');
                $this->addFlash('danger', 'Zbyt wiele nieudanych prób. Spróbuj ponownie za kilkanaście minut.');
            } elseif ($method = $this->twoFactor->verify($user, (string)$request->request->get('code'))) {
                $this->twoFactor->resetAttempts($user);
                $request->getSession()->migrate(true);
                $this->twoFactor->markPassed($request->getSession(), $user);
                $this->audit('auth.2fa_verified', targetType: 'user', label: $user->getUserIdentifier(), details: ['method' => $method]);
                if ($method === TwoFactorService::METHOD_BACKUP) {
                    $left = $this->twoFactor->remainingBackupCodes($user);
                    $this->addFlash($left <= 2 ? 'warning' : 'info', sprintf('Użyto kodu zapasowego. Pozostało kodów: %d.%s', $left,
                        $left <= 2 ? ' Wygeneruj nowe w ustawieniach weryfikacji dwuetapowej.' : ''));
                }
                return $this->redirectToRoute('antispam_start');
            } else {
                $yk = $this->twoFactor->lastYubiKeyStatus();
                $this->failed('login', $yk === null ? 'wrong_code' : 'yubikey_' . strtolower($yk));
                $this->addFlash('danger', $yk === null ? 'Nieprawidłowy kod.' : ($yk === 'UNKNOWN_KEY' ? 'Ten klucz YubiKey nie jest przypisany do Twojego konta.' : YubicoOtpClient::describe($yk)));
            }
        }

        return $this->render('@Antispam/TwoFactor/verify.html.twig', [
            'backup_allowed' => $user instanceof User && $user->isTotpEnabled(),
            'totp' => $user instanceof User ? $user->isTotpEnabled() : $this->twoFactor->hasEnvSecret(),
            'yubikey' => $this->twoFactor->hasYubiKey($user),
        ]);
    }

    /** Own 2FA: status, setup (QR + confirmation), backup codes, disable. */
    #[Route('/my/2fa', name: 'antispam_my_2fa', methods: ['GET'])]
    public function settingsAction(Request $request): Response
    {
        $user = $this->getUser();
        $vars = [
            'env_admin' => $this->twoFactor->isEnvAdmin($user),
            // TOTP section; YubiKeys have their own section below.
            'enabled' => $user instanceof User ? $user->isTotpEnabled() : $this->twoFactor->hasEnvSecret(),
            'required' => $this->twoFactor->needsSetup($user),
            'remaining_codes' => $this->twoFactor->remainingBackupCodes($user),
            'enabled_at' => $user instanceof User ? $user->getTotpEnabledAt() : null,
            'yubikey_configured' => $this->yubiKeys?->isConfigured() ?? false,
            'yubikey_passwordless' => $this->yubiKeys?->isPasswordlessEnabled() ?? false,
            'yubikeys' => $this->yubiKeys && YubiKeyService::canOwnKeys($user) ? $this->safeKeys($user) : [],
        ];
        if ($user instanceof User && !$user->isTotpEnabled()) {
            $secret = $this->twoFactor->pendingSecret($request->getSession());
            $uri = $this->twoFactor->provisioningUri($user, $secret);
            $vars += [
                'secret' => trim(chunk_split($secret, 4, ' ')),
                'qr' => $this->qr->svgDataUri($uri),
            ];
        }
        return $this->render('@Antispam/TwoFactor/settings.html.twig', $vars);
    }

    #[Route('/my/2fa/enable', name: 'antispam_my_2fa_enable', methods: ['POST'])]
    public function enableAction(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user instanceof User || $user->isTotpEnabled()) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->isCsrfTokenValid('my_2fa', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->twoFactor->consumeAttempt($user)) {
            $this->failed('enable', 'throttled');
            $this->addFlash('danger', 'Zbyt wiele nieudanych prób. Spróbuj ponownie za kilkanaście minut.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $secret = $this->twoFactor->pendingSecret($request->getSession());
        $counter = $this->twoFactor->verifyPendingSecret($secret, (string)$request->request->get('code'));
        if ($counter === null) {
            $this->failed('enable', 'wrong_code');
            $this->addFlash('danger', 'Nieprawidłowy kod - sprawdź godzinę w telefonie i wpisz aktualny kod z aplikacji.');
            return $this->redirectToRoute('antispam_my_2fa');
        }

        $codes = $this->twoFactor->enable($user, $secret, $counter);
        $this->twoFactor->resetAttempts($user);
        $this->twoFactor->discardPendingSecret($request->getSession());
        // This session already proved the second factor.
        $this->twoFactor->markPassed($request->getSession(), $user);
        $this->audit('auth.2fa_enabled', targetType: 'user', targetId: $user->getId(), label: $user->getUsername());
        $this->addFlash('success', 'Weryfikacja dwuetapowa jest włączona.');

        return $this->render('@Antispam/TwoFactor/backup_codes.html.twig', ['codes' => $codes]);
    }

    #[Route('/my/2fa/disable', name: 'antispam_my_2fa_disable', methods: ['POST'])]
    public function disableAction(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user instanceof User || !$user->isTotpEnabled()) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->twoFactor->canDropFactor($user, TwoFactorService::METHOD_TOTP)) {
            $this->addFlash('danger', 'Weryfikacja dwuetapowa jest wymagana dla administratorów - nie można jej wyłączyć (najpierw zarejestruj klucz YubiKey).');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->checkPasswordAndCode($request, $user, 'disable')) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $this->twoFactor->disable($user);
        if (!$this->twoFactor->isEnabled($user)) {
            $this->twoFactor->clearPassed($request->getSession());
        }
        $this->audit('auth.2fa_disabled', targetType: 'user', targetId: $user->getId(), label: $user->getUsername());
        $this->addFlash('success', 'Weryfikacja dwuetapowa została wyłączona.');
        return $this->redirectToRoute('antispam_my_2fa');
    }

    #[Route('/my/2fa/backup-codes', name: 'antispam_my_2fa_backup_codes', methods: ['POST'])]
    public function backupCodesAction(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user instanceof User || !$user->isTotpEnabled()) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->checkPasswordAndCode($request, $user, 'backup_codes')) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $codes = $this->twoFactor->regenerateBackupCodes($user);
        $this->audit('auth.2fa_backup_codes', targetType: 'user', targetId: $user->getId(), label: $user->getUsername());
        $this->addFlash('success', 'Wygenerowano nowe kody zapasowe - poprzednie przestały działać.');
        return $this->render('@Antispam/TwoFactor/backup_codes.html.twig', ['codes' => $codes]);
    }

    /**
     * Register a YubiKey: name + the OTP the key typed + current password.
     * The OTP is validated by the Yubico server before the key is stored.
     */
    #[Route('/my/yubikey/add', name: 'antispam_my_yubikey_add', methods: ['POST'])]
    public function yubiKeyAddAction(Request $request): Response
    {
        $user = $this->getUser();
        if (!YubiKeyService::canOwnKeys($user) || !$this->yubiKeys) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->isCsrfTokenValid('my_2fa', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->twoFactor->consumeAttempt($user)) {
            $this->failed('yubikey_add', 'throttled');
            $this->addFlash('danger', 'Zbyt wiele nieudanych prób. Spróbuj ponownie za kilkanaście minut.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->hasher->isPasswordValid($user, (string)$request->request->get('current'))) {
            $this->failed('yubikey_add', 'wrong_password');
            $this->addFlash('danger', 'Obecne hasło jest nieprawidłowe.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $wasEnabled = $this->twoFactor->isEnabled($user);
        $result = $this->yubiKeys->register($user, (string)$request->request->get('otp'), (string)$request->request->get('name'));
        if (is_string($result)) {
            $this->failed('yubikey_add', 'rejected');
            $this->addFlash('danger', $result);
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $this->twoFactor->resetAttempts($user);
        if (!$wasEnabled) {
            // This session just proved the key - it is the second factor now.
            $this->twoFactor->markPassed($request->getSession(), $user);
        }
        $this->audit('auth.yubikey_added', targetType: 'user', targetId: $user instanceof User ? $user->getId() : null, label: $user->getUserIdentifier(),
            details: ['public_id' => $result->getPublicId(), 'name' => $result->getName()]);
        $this->addFlash('success', sprintf('Zarejestrowano klucz „%s” (%s).', $result->getName(), $result->getPublicId()));
        return $this->redirectToRoute('antispam_my_2fa');
    }

    /** Remove one own YubiKey (current password required). */
    #[Route('/my/yubikey/{id}/remove', name: 'antispam_my_yubikey_remove', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function yubiKeyRemoveAction(int $id, Request $request): Response
    {
        $user = $this->getUser();
        if (!YubiKeyService::canOwnKeys($user) || !$this->yubiKeys) {
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->isCsrfTokenValid('my_2fa', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if ($user instanceof User && !$this->twoFactor->canDropFactor($user, TwoFactorService::METHOD_YUBIKEY)) {
            $this->addFlash('danger', 'Weryfikacja dwuetapowa jest wymagana dla administratorów - to Twój jedyny drugi składnik, nie można go usunąć.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->twoFactor->consumeAttempt($user)) {
            $this->failed('yubikey_remove', 'throttled');
            $this->addFlash('danger', 'Zbyt wiele nieudanych prób. Spróbuj ponownie za kilkanaście minut.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        if (!$this->hasher->isPasswordValid($user, (string)$request->request->get('current'))) {
            $this->failed('yubikey_remove', 'wrong_password');
            $this->addFlash('danger', 'Obecne hasło jest nieprawidłowe.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $key = $this->yubiKeys->remove($user, $id);
        if (!$key) {
            $this->addFlash('danger', 'Nie znaleziono klucza.');
            return $this->redirectToRoute('antispam_my_2fa');
        }
        $this->twoFactor->resetAttempts($user);
        $this->audit('auth.yubikey_removed', targetType: 'user', targetId: $user instanceof User ? $user->getId() : null, label: $user->getUserIdentifier(),
            details: ['public_id' => $key->getPublicId(), 'name' => $key->getName()]);
        $this->addFlash('success', sprintf('Usunięto klucz „%s”.', $key->getName()));
        return $this->redirectToRoute('antispam_my_2fa');
    }

    /** Keys of the user; the env admin page must render also when the database is down. */
    private function safeKeys($user): array
    {
        try {
            return $this->yubiKeys->keysOf($user);
        } catch (\Throwable $e) {
            return [];
        }
    }

    /** CSRF + rate limit + current password + a current code (TOTP or backup). */
    private function checkPasswordAndCode(Request $request, User $user, string $step): bool
    {
        if (!$this->isCsrfTokenValid('my_2fa', (string)$request->request->get('_token'))) {
            $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie');
            return false;
        }
        if (!$this->twoFactor->consumeAttempt($user)) {
            $this->failed($step, 'throttled');
            $this->addFlash('danger', 'Zbyt wiele nieudanych prób. Spróbuj ponownie za kilkanaście minut.');
            return false;
        }
        if (!$this->hasher->isPasswordValid($user, (string)$request->request->get('current'))) {
            $this->failed($step, 'wrong_password');
            $this->addFlash('danger', 'Obecne hasło jest nieprawidłowe.');
            return false;
        }
        if ($this->twoFactor->verify($user, (string)$request->request->get('code')) === null) {
            $this->failed($step, 'wrong_code');
            $this->addFlash('danger', 'Nieprawidłowy kod.');
            return false;
        }
        $this->twoFactor->resetAttempts($user);
        return true;
    }

    private function failed(string $step, string $reason): void
    {
        $user = $this->getUser();
        $this->audit('auth.2fa_failed', targetType: 'user', label: $user?->getUserIdentifier(), details: ['step' => $step, 'reason' => $reason]);
    }
}
