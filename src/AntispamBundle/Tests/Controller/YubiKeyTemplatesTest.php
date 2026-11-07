<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\User;
use AntispamBundle\Entity\YubiKey;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * YubiKey UI: API settings on the users page, key list / registration on
 * /my/2fa, the key prompt of /2fa and "Zaloguj kluczem YubiKey" on the
 * login card.
 */
class YubiKeyTemplatesTest extends KernelTestCase
{
    private function render(string $template, array $vars, ?object $user, string $route): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/x');
        $request->attributes->set('_route', $route);
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        if ($user) {
            $c->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        }
        return $c->get('twig')->render($template, $vars);
    }

    private function key(User $user): YubiKey
    {
        $key = new YubiKey($user, 'cccccbcdefgh', 'Brelok');
        (new \ReflectionProperty(YubiKey::class, 'id'))->setValue($key, 3);
        return $key;
    }

    public function testUsersPageHasApiSettingsAndKeyCount()
    {
        $ola = TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola');
        $html = $this->render('@Antispam/User/index.html.twig', [
            'users' => [$ola], 'env_admin' => 'admin', 'two_factor_required' => false, 'env_admin_2fa' => false,
            'yubikey' => ['configured' => true, 'client_id' => '123', 'has_secret' => true, 'api_url' => '', 'default_url' => 'https://api.yubico.com/wsapi/2.0/verify', 'passwordless' => true, 'counts' => [8 => 2]],
        ], new InMemoryUser('admin', 'x', ['ROLE_ADMIN']), 'antispam_user_index');

        $this->assertStringContainsString('action="/users/yubikey-settings"', $html);
        $this->assertStringContainsString('name="client_id" value="123"', $html);
        $this->assertStringNotContainsString('value="' . 'enc:', $html, 'secret never rendered');
        $this->assertStringContainsString('YubiKey: 2', $html);
        $this->assertStringContainsString('formaction="/users/2fa-reset/8"', $html, 'reset offered for a user with keys only');
    }

    public function testOwnSettingsListAndRegister()
    {
        $jan = TwoFactorFixtures::user(User::ROLE_USER, 7, 'jan');
        $html = $this->render('@Antispam/TwoFactor/settings.html.twig', [
            'env_admin' => false, 'enabled' => false, 'required' => false, 'remaining_codes' => 0, 'enabled_at' => null,
            'secret' => 'ABCD', 'qr' => 'data:image/svg+xml;base64,', 'yubikey_configured' => true, 'yubikey_passwordless' => true,
            'yubikeys' => [$this->key($jan)],
        ], $jan, 'antispam_my_2fa');

        $this->assertStringContainsString('cccccbcdefgh', $html);
        $this->assertStringContainsString('action="/my/yubikey/3/remove"', $html);
        $this->assertStringContainsString('action="/my/yubikey/add"', $html);
        $this->assertStringContainsString('Zaloguj kluczem YubiKey', $html);
    }

    public function testVerifyPromptsForKey()
    {
        $html = $this->render('@Antispam/TwoFactor/verify.html.twig', ['backup_allowed' => false, 'totp' => false, 'yubikey' => true],
            TwoFactorFixtures::user(), 'antispam_2fa_verify');
        $this->assertStringContainsString('dotknij przycisku na kluczu', $html);
        $this->assertStringContainsString('maxlength="64"', $html);
    }

    public function testLoginCardOffersKeyLogin()
    {
        $vars = ['last_username' => '', 'error' => null];
        $off = $this->render('@Antispam/Home/index.html.twig', $vars, null, 'antispam_home');
        $this->assertStringNotContainsString('/login/yubikey', $off);

        $on = $this->render('@Antispam/Home/index.html.twig', $vars + ['yubikey_login' => true], null, 'antispam_home');
        $this->assertStringContainsString('action="/login/yubikey"', $on);
        $this->assertStringContainsString('name="otp"', $on);
    }
}
