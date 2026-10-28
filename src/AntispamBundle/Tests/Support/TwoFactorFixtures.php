<?php

namespace AntispamBundle\Tests\Support;

use AntispamBundle\Entity\User;
use AntispamBundle\Security\TwoFactor\Totp;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;

/**
 * TwoFactorService with an in-memory config table, an in-memory rate limiter
 * and a real CryptoService, plus helpers to create / enrol users.
 */
class TwoFactorFixtures
{
    public const ENV_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    /** @var array<string, mixed> config table */
    public array $config = [];

    public function __construct(private TestCase $test)
    {
        TwoFactorService::$backupHashCost = 4;
    }

    public static function limiter(int $limit = 5): RateLimiterFactory
    {
        return new RateLimiterFactory(['id' => 'two_factor_code', 'policy' => 'sliding_window', 'limit' => $limit, 'interval' => '15 minutes'], new InMemoryStorage());
    }

    public function service(string $envSecret = '', ?RateLimiterFactory $limiter = null): TwoFactorService
    {
        $config = $this->mock(ConfigService::class);
        $config->method('get')->willReturnCallback(fn($k) => $this->config[$k] ?? null);
        $config->method('set')->willReturnCallback(function ($k, $v) {
            $this->config[$k] = $v;
            return true;
        });
        return new TwoFactorService($this->mock(EntityManagerInterface::class), new CryptoService('test-secret'), $config, $limiter ?? self::limiter(), $envSecret);
    }

    public static function user(string $role = User::ROLE_USER, int $id = 7, string $username = 'jan'): User
    {
        $user = (new User())->setUsername($username)->setRole($role)->setPassword('x');
        (new \ReflectionProperty(User::class, 'id'))->setValue($user, $id);
        return $user;
    }

    /**
     * Enable 2FA through the real flow (confirmed step = now - 1).
     *
     * @return array{0: string, 1: string[]} [secret, backup codes]
     */
    public static function enroll(TwoFactorService $tf, User $user): array
    {
        $secret = Totp::generateSecret();
        $codes = $tf->enable($user, $secret, Totp::counterAt() - 1);
        return [$secret, $codes];
    }

    private function mock(string $class): object
    {
        return (new \ReflectionMethod($this->test, 'createMock'))->invoke($this->test, $class);
    }
}
