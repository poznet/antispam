<?php

namespace AntispamBundle\Tests\Security\TwoFactor;

use AntispamBundle\Entity\User;
use AntispamBundle\Security\TwoFactor\Totp;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use AntispamBundle\Services\CryptoService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Core\User\InMemoryUser;

class TwoFactorServiceTest extends TestCase
{
    private TwoFactorFixtures $fx;

    protected function setUp(): void
    {
        $this->fx = new TwoFactorFixtures($this);
    }

    private function service(string $envSecret = '', ?RateLimiterFactory $limiter = null): TwoFactorService
    {
        return $this->fx->service($envSecret, $limiter);
    }

    private static function user(string $role = User::ROLE_USER): User
    {
        return TwoFactorFixtures::user($role);
    }

    private static function enroll(TwoFactorService $tf, User $user): array
    {
        return TwoFactorFixtures::enroll($tf, $user);
    }

    public function testEnableStoresAnEncryptedSecretAndHashedBackupCodes()
    {
        $tf = $this->service();
        $user = self::user();
        [$secret, $codes] = self::enroll($tf, $user);

        $this->assertTrue($user->isTotpEnabled());
        $this->assertTrue($tf->isEnabled($user));
        $this->assertStringStartsWith(CryptoService::PREFIX, $user->getTotpSecret());
        $this->assertStringNotContainsString($secret, $user->getTotpSecret());
        $this->assertCount(TwoFactorService::BACKUP_CODE_COUNT, $codes);
        $this->assertCount(TwoFactorService::BACKUP_CODE_COUNT, array_unique($codes));
        foreach ($user->getTotpBackupCodes() as $i => $hash) {
            $this->assertStringNotContainsString(str_replace('-', '', $codes[$i]), $hash);
            $this->assertTrue(password_verify(str_replace('-', '', $codes[$i]), $hash));
        }
    }

    public function testTotpCodeWorksOnceOnly()
    {
        $tf = $this->service();
        $user = self::user();
        [$secret] = self::enroll($tf, $user);
        $code = Totp::code($secret, Totp::counterAt());

        $this->assertSame(TwoFactorService::METHOD_TOTP, $tf->verify($user, $code));
        $this->assertSame(Totp::counterAt(), $user->getTotpLastCounter());
        $this->assertNull($tf->verify($user, $code), 'replayed code');
        $this->assertNull($tf->verify($user, '000000' === $code ? '111111' : '000000'));
    }

    public function testConfirmationStepCannotBeReplayedAtLogin()
    {
        $tf = $this->service();
        $user = self::user();
        $secret = Totp::generateSecret();
        $code = Totp::code($secret, Totp::counterAt());
        $counter = $tf->verifyPendingSecret($secret, $code);
        $this->assertNotNull($counter);
        $tf->enable($user, $secret, $counter);

        $this->assertNull($tf->verify($user, $code));
    }

    public function testBackupCodeIsConsumed()
    {
        $tf = $this->service();
        $user = self::user();
        [, $codes] = self::enroll($tf, $user);

        $this->assertSame(TwoFactorService::METHOD_BACKUP, $tf->verify($user, strtoupper($codes[3])));
        $this->assertSame(9, $tf->remainingBackupCodes($user));
        $this->assertNull($tf->verify($user, $codes[3]), 'used twice');
        $this->assertSame(TwoFactorService::METHOD_BACKUP, $tf->verify($user, str_replace('-', ' ', $codes[0])));
        $this->assertSame(8, $tf->remainingBackupCodes($user));
    }

    public function testRegeneratedBackupCodesReplaceTheOldOnes()
    {
        $tf = $this->service();
        $user = self::user();
        [, $old] = self::enroll($tf, $user);
        $new = $tf->regenerateBackupCodes($user);

        $this->assertNull($tf->verify($user, $old[0]));
        $this->assertSame(TwoFactorService::METHOD_BACKUP, $tf->verify($user, $new[0]));
    }

    public function testDisableForgetsEverything()
    {
        $tf = $this->service();
        $user = self::user();
        [$secret] = self::enroll($tf, $user);
        $tf->disable($user);

        $this->assertFalse($user->isTotpEnabled());
        $this->assertNull($user->getTotpSecret());
        $this->assertSame([], $user->getTotpBackupCodes());
        $this->assertNull($tf->verify($user, Totp::code($secret, Totp::counterAt())));
    }

    public function testEnvAdminUsesAdminTotpSecretWithReplayProtection()
    {
        $admin = new InMemoryUser('admin', 'hash', ['ROLE_ADMIN']);
        $this->assertFalse($this->service()->isEnabled($admin), 'no ADMIN_TOTP_SECRET');
        $this->assertFalse($this->service('garbage')->isEnabled($admin));

        $tf = $this->service(strtolower(TwoFactorFixtures::ENV_SECRET));
        $this->assertTrue($tf->isEnabled($admin));
        $code = Totp::code(TwoFactorFixtures::ENV_SECRET, Totp::counterAt());
        $this->assertSame(TwoFactorService::METHOD_TOTP, $tf->verify($admin, $code));
        $this->assertNull($tf->verify($admin, $code), 'replay');
        $this->assertSame(0, $tf->remainingBackupCodes($admin));
        $this->assertFalse($tf->needsSetup($admin), 'env admin is never forced into a setup it cannot do');
    }

    public function testEnforcementOnlyConcernsDatabaseAdminsWithout2fa()
    {
        $tf = $this->service();
        $admin = self::user(User::ROLE_ADMIN);
        $this->assertFalse($tf->needsSetup($admin));

        $tf->setRequiredForAdmins(true);
        $this->assertTrue($tf->isRequiredForAdmins());
        $this->assertTrue($tf->needsSetup($admin));
        $this->assertFalse($tf->needsSetup(self::user(User::ROLE_USER)));
        self::enroll($tf, $admin);
        $this->assertFalse($tf->needsSetup($admin));
    }

    public function testRateLimitPerLogin()
    {
        $tf = $this->service('', TwoFactorFixtures::limiter(5));
        $jan = self::user();
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($tf->consumeAttempt($jan));
        }
        $this->assertFalse($tf->consumeAttempt($jan), '6th attempt');
        $this->assertTrue($tf->consumeAttempt(new InMemoryUser('other', 'x')), 'other login unaffected');
        $tf->resetAttempts($jan);
        $this->assertTrue($tf->consumeAttempt($jan));
    }

    public function testSessionMarkerIsBoundToTheUser()
    {
        $tf = $this->service();
        $session = new Session(new MockArraySessionStorage());
        $jan = self::user();
        $this->assertFalse($tf->isPassed($session, $jan));
        $tf->markPassed($session, $jan);
        $this->assertTrue($tf->isPassed($session, $jan));
        $this->assertFalse($tf->isPassed($session, new InMemoryUser('jan', 'x')), 'same login, other provider');
        $tf->clearPassed($session);
        $this->assertFalse($tf->isPassed($session, $jan));
    }

    public function testPendingSecretIsStableUntilDiscarded()
    {
        $tf = $this->service();
        $session = new Session(new MockArraySessionStorage());
        $a = $tf->pendingSecret($session);
        $this->assertSame($a, $tf->pendingSecret($session));
        $tf->discardPendingSecret($session);
        $this->assertNotSame($a, $tf->pendingSecret($session));
    }

    public function testUnreadableSecretFailsClosed()
    {
        $tf = $this->service();
        $user = self::user();
        [$secret] = self::enroll($tf, $user);
        $user->setTotpSecret(CryptoService::PREFIX . base64_encode(str_repeat('x', 60)));
        $this->assertNull($tf->verify($user, Totp::code($secret, Totp::counterAt())));
    }
}
