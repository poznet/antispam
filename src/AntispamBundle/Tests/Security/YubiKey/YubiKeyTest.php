<?php

namespace AntispamBundle\Tests\Security\YubiKey;

use AntispamBundle\Entity\User;
use AntispamBundle\Entity\YubiKey;
use AntispamBundle\Repository\YubiKeyRepository;
use AntispamBundle\Security\AdminUserProvider;
use AntispamBundle\Security\TwoFactor\TwoFactorService;
use AntispamBundle\Security\YubiKey\YubicoOtpClient;
use AntispamBundle\Security\YubiKey\YubiKeyAuthenticator;
use AntispamBundle\Security\YubiKey\YubiKeyLoginBadge;
use AntispamBundle\Security\YubiKey\YubiKeyService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\CustomCredentials;

/**
 * Yubico OTP: validation protocol (signatures, nonce/otp echo, statuses),
 * key registration, YubiKey as the 2FA step and the passwordless login.
 */
class YubiKeyTest extends TestCase
{
    private const CLIENT_ID = '12345';
    private const PUBLIC_ID = 'cccccbcdefgh';
    private const OTP = self::PUBLIC_ID . 'ivlnrtuvcbdefghijklnrtuvcbdefghi';
    private const OTHER_OTP = 'cccccbcdefhh' . 'ivlnrtuvcbdefghijklnrtuvcbdefghi';

    private string $secret;
    private string $answerStatus = 'OK';
    /** Tamper with the answer: 'sig' | 'nonce' | 'otp' | 'http500' | null */
    private ?string $tamper = null;
    /** @var array[] query of every validation request */
    private array $requests = [];
    private array $config = [];
    /** @var YubiKey[] */
    private array $keys = [];

    protected function setUp(): void
    {
        $this->secret = base64_encode(random_bytes(20));
    }

    private function http(): MockHttpClient
    {
        return new MockHttpClient(function (string $method, string $url) {
            parse_str((string)parse_url($url, PHP_URL_QUERY), $q);
            $this->requests[] = $q;
            if ($this->tamper === 'http500') {
                return new MockResponse('err', ['http_code' => 500]);
            }
            $answer = [
                'otp' => $this->tamper === 'otp' ? self::OTHER_OTP : $q['otp'],
                'nonce' => $this->tamper === 'nonce' ? str_repeat('a', 32) : $q['nonce'],
                't' => '2026-11-07T12:00:00Z0123',
                'status' => $this->answerStatus,
            ];
            $answer['h'] = YubicoOtpClient::sign($answer, base64_decode($this->secret));
            if ($this->tamper === 'sig') {
                $answer['h'] = base64_encode(str_repeat("\0", 20));
            }
            $body = '';
            foreach ($answer as $k => $v) {
                $body .= "$k=$v\r\n";
            }
            return new MockResponse($body);
        });
    }

    private function client(): YubicoOtpClient
    {
        return new YubicoOtpClient($this->http());
    }

    private function service(bool $configured = true, bool $passwordless = true): YubiKeyService
    {
        $crypto = new CryptoService('test-secret');
        if ($configured) {
            $this->config = [
                YubiKeyService::CONFIG_CLIENT_ID => self::CLIENT_ID,
                YubiKeyService::CONFIG_SECRET => $crypto->encrypt($this->secret),
                YubiKeyService::CONFIG_PASSWORDLESS => $passwordless ? '1' : '0',
            ];
        }
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnCallback(fn($k) => $this->config[$k] ?? null);
        $config->method('set')->willReturnCallback(function ($k, $v) {
            $this->config[$k] = $v;
            return true;
        });

        $test = $this;
        $repo = new class($test) extends YubiKeyRepository {
            public function __construct(private YubiKeyTest $t)
            {
            }

            public function findByUser(User $user): array
            {
                return array_values(array_filter($this->t->keys(), fn(YubiKey $k) => $k->getUser()?->getId() === $user->getId()));
            }

            public function findByAdminLogin(string $login): array
            {
                return array_values(array_filter($this->t->keys(), fn(YubiKey $k) => $k->getUser() === null && $k->getAdminLogin() === $login));
            }

            public function findOneByPublicId(string $publicId): ?YubiKey
            {
                foreach ($this->t->keys() as $k) {
                    if ($k->getPublicId() === $publicId) {
                        return $k;
                    }
                }
                return null;
            }

            public function find(mixed $id, $lockMode = null, $lockVersion = null): ?object
            {
                foreach ($this->t->keys() as $k) {
                    if ($k->getId() == $id) {
                        return $k;
                    }
                }
                return null;
            }
        };
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($repo);
        $em->method('persist')->willReturnCallback(function (YubiKey $k) {
            (new \ReflectionProperty(YubiKey::class, 'id'))->setValue($k, count($this->keys) + 1);
            $this->keys[] = $k;
        });
        $em->method('remove')->willReturnCallback(function (YubiKey $k) {
            $this->keys = array_values(array_filter($this->keys, fn($x) => $x !== $k));
        });

        return new YubiKeyService($em, $config, $crypto, $this->client());
    }

    /** @internal for the in-memory repository */
    public function keys(): array
    {
        return $this->keys;
    }

    /* ----- protocol ------------------------------------------------------- */

    public function testOtpSyntaxAndPublicId()
    {
        $this->assertTrue(YubicoOtpClient::isOtp(self::OTP));
        $this->assertTrue(YubicoOtpClient::isOtp(' ' . strtoupper(self::OTP) . "\n"));
        $this->assertSame(self::PUBLIC_ID, YubicoOtpClient::publicId(self::OTP));
        $this->assertFalse(YubicoOtpClient::isOtp('123456'));
        $this->assertFalse(YubicoOtpClient::isOtp('abcde-fghjk'));
        $this->assertFalse(YubicoOtpClient::isOtp(substr(self::OTP, 12)), 'no public id');
        $this->assertFalse(YubicoOtpClient::isOtp(str_replace('c', 'a', self::OTP)), 'not modhex');
    }

    public function testValidOtpIsSignedAndAccepted()
    {
        $this->assertSame('OK', $this->client()->verify(self::OTP, self::CLIENT_ID, $this->secret));
        $q = $this->requests[0];
        $this->assertSame(self::CLIENT_ID, $q['id']);
        $this->assertSame(self::OTP, $q['otp']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $q['nonce']);
        $h = $q['h'];
        unset($q['h']);
        $this->assertSame(YubicoOtpClient::sign($q, base64_decode($this->secret)), $h, 'request signed with the Secret Key');
    }

    public function testTamperedAnswersAreRejected()
    {
        foreach (['sig', 'nonce', 'otp'] as $tamper) {
            $this->tamper = $tamper;
            $this->assertSame(YubicoOtpClient::STATUS_BAD_RESPONSE, $this->client()->verify(self::OTP, self::CLIENT_ID, $this->secret), $tamper);
        }
        $this->tamper = 'http500';
        $this->assertSame(YubicoOtpClient::STATUS_BACKEND_ERROR, $this->client()->verify(self::OTP, self::CLIENT_ID, $this->secret));
    }

    public function testErrorStatusIsReturned()
    {
        $this->answerStatus = 'REPLAYED_OTP';
        $this->assertSame('REPLAYED_OTP', $this->client()->verify(self::OTP, self::CLIENT_ID, $this->secret));
        $this->assertSame(YubicoOtpClient::STATUS_BAD_OTP, $this->client()->verify('123456', self::CLIENT_ID, $this->secret));
    }

    /* ----- registration + 2FA ------------------------------------------- */

    public function testRegisterValidatesAndRejectsDuplicates()
    {
        $yk = $this->service();
        $jan = TwoFactorFixtures::user(User::ROLE_USER, 7, 'jan');
        $this->answerStatus = 'BAD_OTP';
        $this->assertIsString($yk->register($jan, self::OTP, 'brelok'));
        $this->assertSame([], $this->keys);

        $this->answerStatus = 'OK';
        $key = $yk->register($jan, self::OTP, 'brelok');
        $this->assertInstanceOf(YubiKey::class, $key);
        $this->assertSame(self::PUBLIC_ID, $key->getPublicId());
        $this->assertSame('Ten klucz jest już zarejestrowany.', $yk->register(TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola'), self::OTP, 'x'));
        $this->assertIsString($this->service(false)->register($jan, self::OTP, 'x'), 'not configured');
    }

    public function testYubiKeyIsSecondFactor()
    {
        $yk = $this->service();
        $fx = new TwoFactorFixtures($this);
        $tf = new TwoFactorService($this->createMock(EntityManagerInterface::class), new CryptoService('test-secret'),
            $this->createMock(ConfigService::class), TwoFactorFixtures::limiter(), '', $yk);
        $jan = TwoFactorFixtures::user(User::ROLE_USER, 7, 'jan');
        $ola = TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola');
        $this->assertFalse($tf->isEnabled($jan));
        $yk->register($jan, self::OTP, 'brelok');

        $this->assertTrue($tf->isEnabled($jan), 'a key alone turns 2FA on');
        $this->assertSame(TwoFactorService::METHOD_YUBIKEY, $tf->verify($jan, self::OTP));
        $this->assertNull($tf->verify($ola, self::OTP), 'foreign key');
        $this->assertSame('UNKNOWN_KEY', $tf->lastYubiKeyStatus());
        $this->answerStatus = 'REPLAYED_OTP';
        $this->assertNull($tf->verify($jan, self::OTP));
        $this->assertSame('REPLAYED_OTP', $tf->lastYubiKeyStatus());

        // API settings removed: keys are ignored, no lockout.
        $this->config = [];
        $this->assertFalse($tf->isEnabled($jan));
    }

    public function testSettingsValidationAndEncryptedSecret()
    {
        $yk = $this->service(false);
        $this->assertNotEmpty($yk->saveSettings('abc', 'not base64!', 'http://x', true));
        $this->assertSame([], $this->config);
        $this->assertSame([], $yk->saveSettings('999', $this->secret, '', true));
        $this->assertStringStartsWith('enc:v1:', $this->config[YubiKeyService::CONFIG_SECRET]);
        $this->assertTrue($yk->isConfigured());
        $this->assertTrue($yk->isPasswordlessEnabled());
        $yk->saveSettings('999', null, '', false);
        $this->assertTrue($yk->hasSecret(), 'null keeps the secret');
        $this->assertFalse($yk->isPasswordlessEnabled());
    }

    /* ----- passwordless login ------------------------------------------- */

    private function authenticator(YubiKeyService $yk, int $limit = 10, ?AdminUserProvider $admins = null): YubiKeyAuthenticator
    {
        $urls = $this->createMock(UrlGeneratorInterface::class);
        $urls->method('generate')->willReturnCallback(fn($n) => '/' . $n);
        $limiter = new RateLimiterFactory(['id' => 'yubikey_login', 'policy' => 'sliding_window', 'limit' => $limit, 'interval' => '15 minutes'], new InMemoryStorage());
        return new YubiKeyAuthenticator($yk, $urls, $limiter, null, $admins);
    }

    /* ----- built-in ADMIN_USER ------------------------------------------- */

    public function testEnvAdminKeys()
    {
        $yk = $this->service();
        $tf = new TwoFactorService($this->createMock(EntityManagerInterface::class), new CryptoService('test-secret'),
            $this->createMock(ConfigService::class), TwoFactorFixtures::limiter(), '', $yk);
        $admin = new InMemoryUser('admin', 'hash', ['ROLE_ADMIN']);
        $this->assertFalse($tf->isEnabled($admin));

        $key = $yk->register($admin, self::OTP, 'awaryjny');
        $this->assertInstanceOf(YubiKey::class, $key);
        $this->assertNull($key->getUser());
        $this->assertSame('admin', $key->getAdminLogin());
        $this->assertTrue($tf->isEnabled($admin), 'env admin with a key needs the key after the password');
        $this->assertSame(TwoFactorService::METHOD_YUBIKEY, $tf->verify($admin, self::OTP));

        // A database user with the same key id cannot use it, nor another env login.
        $this->assertNull($tf->verify(TwoFactorFixtures::user(User::ROLE_ADMIN, 7, 'admin'), self::OTP));
        $this->assertNull($tf->verify(new InMemoryUser('root', 'hash', ['ROLE_ADMIN']), self::OTP));
        $this->assertNull($yk->remove(TwoFactorFixtures::user(User::ROLE_ADMIN, 7, 'admin'), $key->getId()), 'no IDOR');

        // Passwordless: loaded through AdminUserProvider (still that login).
        $auth = $this->authenticator($yk, 10, new AdminUserProvider('admin', 'hash'));
        $passport = $auth->authenticate($this->loginRequest(self::OTP));
        $this->assertInstanceOf(InMemoryUser::class, $passport->getUser());
        $this->assertSame('admin', $passport->getUser()->getUserIdentifier());
        $passport = $this->authenticator($yk, 10, new AdminUserProvider('nowy', 'hash'))->authenticate($this->loginRequest(self::OTP));
        try {
            $passport->getUser();
            $this->fail('ADMIN_USER renamed: the old key must not log in');
        } catch (\Symfony\Component\Security\Core\Exception\UserNotFoundException $e) {
        }

        $this->assertSame($key, $yk->remove($admin, $key->getId()));
        $this->assertFalse($tf->isEnabled($admin));
    }

    private function loginRequest(string $otp): Request
    {
        $r = Request::create('/login/yubikey', 'POST', ['otp' => $otp, '_csrf_token' => 't']);
        $r->attributes->set('_route', YubiKeyAuthenticator::ROUTE);
        $r->setSession(new Session(new MockArraySessionStorage()));
        return $r;
    }

    public function testPasswordlessLogin()
    {
        $yk = $this->service();
        $jan = TwoFactorFixtures::user(User::ROLE_ADMIN, 7, 'jan');
        $yk->register($jan, self::OTP, 'brelok');
        $auth = $this->authenticator($yk);

        $request = $this->loginRequest(self::OTP);
        $this->assertTrue($auth->supports($request));
        $passport = $auth->authenticate($request);
        $this->assertSame($jan, $passport->getUser());
        $this->assertTrue($passport->hasBadge(YubiKeyLoginBadge::class));
        $credentials = $passport->getBadge(CustomCredentials::class);
        $credentials->executeCustomChecker($jan);
        $this->assertTrue($credentials->isResolved());

        $this->answerStatus = 'REPLAYED_OTP';
        $passport = $auth->authenticate($this->loginRequest(self::OTP));
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $passport->getBadge(CustomCredentials::class)->executeCustomChecker($jan);
    }

    public function testPasswordlessRefusals()
    {
        $yk = $this->service(true, false);
        $jan = TwoFactorFixtures::user(User::ROLE_USER, 7, 'jan');
        $yk->register($jan, self::OTP, 'brelok');
        $messages = [];
        // The config table is shared by the services of this test: build each one right before use.
        foreach ([[fn() => $yk, self::OTP], [fn() => $this->service(), self::OTHER_OTP], [fn() => $this->service(), '123456']] as [$service, $otp]) {
            try {
                $this->authenticator($service())->authenticate($this->loginRequest($otp));
                $messages[] = 'accepted';
            } catch (CustomUserMessageAuthenticationException $e) {
                $messages[] = $e->getMessageKey();
            }
        }
        $this->assertStringContainsString('wyłączone', $messages[0]);
        $this->assertStringContainsString('nie jest zarejestrowany', $messages[1]);
        $this->assertStringContainsString('To nie jest kod', $messages[2]);

        $auth = $this->authenticator($this->service(), 2);
        for ($i = 0; $i < 3; $i++) {
            try {
                $auth->authenticate($this->loginRequest('123456'));
            } catch (CustomUserMessageAuthenticationException $e) {
                $last = $e->getMessageKey();
            }
        }
        $this->assertStringContainsString('Zbyt wiele', $last);
    }
}
