<?php

namespace AntispamBundle\Tests\Security\TwoFactor;

use AntispamBundle\Security\TwoFactor\Totp;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The real firewall + TwoFactorGuard wiring, with the environment admin and
 * ADMIN_TOTP_SECRET (no database needed): every panel page waits for the
 * code, the code form is throttled, a valid code opens the session.
 */
class TwoFactorWebTest extends WebTestCase
{
    private const ADMIN_HASH = 'test-admin-hash';

    protected function setUp(): void
    {
        $_SERVER['ADMIN_PASSWORD_HASH'] = $_ENV['ADMIN_PASSWORD_HASH'] = self::ADMIN_HASH;
        $_SERVER['ADMIN_USER'] = $_ENV['ADMIN_USER'] = 'admin';
        $_SERVER['ADMIN_TOTP_SECRET'] = $_ENV['ADMIN_TOTP_SECRET'] = TwoFactorFixtures::ENV_SECRET;
    }

    protected function tearDown(): void
    {
        unset($_SERVER['ADMIN_PASSWORD_HASH'], $_ENV['ADMIN_PASSWORD_HASH'], $_SERVER['ADMIN_USER'], $_ENV['ADMIN_USER'],
            $_SERVER['ADMIN_TOTP_SECRET'], $_ENV['ADMIN_TOTP_SECRET']);
        parent::tearDown();
    }

    private function client(): KernelBrowser
    {
        $client = static::createClient();
        // The limiter state lives in the test cache between runs.
        self::getContainer()->get('limiter.two_factor_code')->create('2fa-admin')->reset();
        $client->loginUser(new InMemoryUser('admin', self::ADMIN_HASH, ['ROLE_ADMIN']));
        return $client;
    }

    public function testPanelPagesWaitForTheCode()
    {
        $client = $this->client();
        foreach (['/panel', '/users', '/my/quarantine', '/my/2fa', '/audit'] as $path) {
            $client->request('GET', $path);
            $this->assertResponseRedirects('/2fa', null, $path);
        }
        $client->request('GET', '/health');
        $this->assertNotSame('/2fa', $client->getResponse()->headers->get('Location'), 'public paths are not guarded');
    }

    public function testValidCodeOpensTheSession()
    {
        $client = $this->client();
        $crawler = $client->request('GET', '/2fa');
        $this->assertResponseIsSuccessful();
        $form = $crawler->filterXPath('//form[contains(@action, "/2fa")]')->form(['code' => Totp::code(TwoFactorFixtures::ENV_SECRET, Totp::counterAt())]);
        $client->submit($form);
        $this->assertResponseRedirects('/start');

        $client->request('GET', '/2fa');
        $this->assertResponseRedirects('/start', null, 'nothing pending any more');
    }

    public function testCodeStepIsThrottledAndCsrfProtected()
    {
        $client = $this->client();
        $crawler = $client->request('GET', '/2fa');
        $token = $crawler->filterXPath('//form[contains(@action, "/2fa")]//input[@name="_token"]')->attr('value');
        $good = Totp::code(TwoFactorFixtures::ENV_SECRET, Totp::counterAt());
        $wrong = $good === '000000' ? '111111' : '000000';

        $client->request('POST', '/2fa', ['code' => $good, '_token' => 'forged']);
        $client->request('GET', '/panel');
        $this->assertResponseRedirects('/2fa', null, 'forged CSRF token does not pass');

        for ($i = 0; $i < 5; $i++) {
            $client->request('POST', '/2fa', ['code' => $wrong, '_token' => $token]);
            $this->assertResponseIsSuccessful();
            $this->assertStringContainsString('Nieprawidłowy kod', $client->getResponse()->getContent());
        }
        $client->request('POST', '/2fa', ['code' => $good, '_token' => $token]);
        $this->assertResponseIsSuccessful();
        $this->assertStringContainsString('Zbyt wiele', $client->getResponse()->getContent());
        $client->request('GET', '/panel');
        $this->assertResponseRedirects('/2fa');
    }
}
