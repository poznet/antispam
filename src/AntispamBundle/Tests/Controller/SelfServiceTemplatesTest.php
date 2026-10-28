<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\User;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * The user-area pages (/my/spam, /my/rules, /my/2fa, /2fa) and the users list
 * render with stub data; forms carry CSRF tokens; the user menu points
 * "Spam" at /my/spam and keeps the score log as "Dziennik ocen".
 */
class SelfServiceTemplatesTest extends KernelTestCase
{
    private function render(string $template, array $vars, object $user, string $route): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/my/x');
        $request->attributes->set('_route', $route);
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        return $c->get('twig')->render($template, $vars);
    }

    private function user(): User
    {
        return TwoFactorFixtures::user(User::ROLE_USER);
    }

    public function testSpamPageAndUserMenu()
    {
        $html = $this->render('@Antispam/My/spam.html.twig', ['limit' => 100, 'mailboxes' => [
            ['key' => 'imap-5', 'label' => 'Jan', 'total' => 2, 'error' => null, 'items' => [
                ['id' => '3', 'from' => 'a@b.pl', 'from_name' => 'A', 'subject' => 'Promo', 'date' => new \DateTimeImmutable(), 'score' => 12, 'labels' => ['x'], 'high_risk' => false, 'uidvalidity' => 42],
                ['id' => '4', 'from' => 'c@d.pl', 'from_name' => '', 'subject' => 'Faktura', 'date' => null, 'score' => null, 'labels' => [], 'high_risk' => true, 'uidvalidity' => 42],
            ]],
            ['key' => 'ssh-7', 'label' => 'SSH', 'total' => 0, 'error' => 'Nie udało się', 'items' => []],
        ]], $this->user(), 'antispam_my_spam');

        $this->assertStringContainsString('action="/my/spam/action"', $html);
        $this->assertSame(2, substr_count($html, 'name="_token"'));
        $this->assertSame(1, substr_count($html, 'value="whitelist"'), 'no "always accept" for the high-risk one');
        $this->assertStringContainsString('name="uidvalidity" value="42"', $html);
        $this->assertMatchesRegularExpression('~<a href="/my/spam" class="active"[^>]*>\s*<span[^>]*></span> Spam~', $html);
        $this->assertMatchesRegularExpression('~<a href="/my/scorelog"[^>]*>\s*<span[^>]*></span> Dziennik ocen~', $html);
        $this->assertStringContainsString('href="/my/rules"', $html);
        $this->assertStringContainsString('href="/my/2fa"', $html);
    }

    public function testRulesPage()
    {
        $rule = (new EmailWhitelist())->setEmail('jan@firma.pl')->setWhitelistemail('szef@firma.pl')->setPatternType('exact');
        (new \ReflectionProperty(EmailWhitelist::class, 'id'))->setValue($rule, 11);
        $lists = [];
        foreach (['whitelist' => 'host', 'email_whitelist' => 'whitelistemail', 'blacklist' => 'host', 'email_blacklist' => 'blacklistemail'] as $k => $f) {
            $lists[$k] = ['label' => $k, 'field' => $f, 'rules' => $k === 'email_whitelist' ? [$rule] : []];
        }
        $html = $this->render('@Antispam/My/rules.html.twig', ['lists' => $lists, 'owners' => ['jan@firma.pl'], 'ssh_owners' => []], $this->user(), 'antispam_my_rules');

        $this->assertStringContainsString('szef@firma.pl', $html);
        $this->assertStringContainsString('action="/my/rules/delete"', $html);
        $this->assertStringContainsString('name="id" value="11"', $html);
        $this->assertStringNotContainsString('value="regex"', $html, 'no regex option for users');
        $this->assertStringNotContainsString('value="*"', $html, 'no global owner');
    }

    public function testTwoFactorPages()
    {
        $setup = $this->render('@Antispam/TwoFactor/settings.html.twig', [
            'env_admin' => false, 'enabled' => false, 'required' => true, 'remaining_codes' => 0, 'enabled_at' => null,
            'secret' => 'ABCD EFGH', 'qr' => 'data:image/svg+xml;base64,PHN2Zy8+',
        ], $this->user(), 'antispam_my_2fa');
        $this->assertStringContainsString('src="data:image/svg+xml;base64,PHN2Zy8+"', $setup);
        $this->assertStringContainsString('action="/my/2fa/enable"', $setup);
        $this->assertStringContainsString('musi mieć włączoną', $setup);

        $enabled = $this->render('@Antispam/TwoFactor/settings.html.twig', [
            'env_admin' => false, 'enabled' => true, 'required' => false, 'remaining_codes' => 2, 'enabled_at' => new \DateTime(),
        ], $this->user(), 'antispam_my_2fa');
        $this->assertStringContainsString('action="/my/2fa/disable"', $enabled);
        $this->assertStringContainsString('action="/my/2fa/backup-codes"', $enabled);

        $env = $this->render('@Antispam/TwoFactor/settings.html.twig', ['env_admin' => true, 'enabled' => false, 'required' => false, 'remaining_codes' => 0, 'enabled_at' => null],
            new InMemoryUser('admin', 'x', ['ROLE_ADMIN']), 'antispam_my_2fa');
        $this->assertStringContainsString('ADMIN_TOTP_SECRET', $env);

        $verify = $this->render('@Antispam/TwoFactor/verify.html.twig', ['backup_allowed' => true], $this->user(), 'antispam_2fa_verify');
        $this->assertStringContainsString('autocomplete="one-time-code"', $verify);

        $codes = $this->render('@Antispam/TwoFactor/backup_codes.html.twig', ['codes' => ['abcde-fghjk']], $this->user(), 'antispam_my_2fa_enable');
        $this->assertStringContainsString('abcde-fghjk', $codes);
    }

    public function testUsersListShows2faAndReset()
    {
        $tf = (new TwoFactorFixtures($this))->service();
        $ola = TwoFactorFixtures::user(User::ROLE_USER, 8, 'ola');
        TwoFactorFixtures::enroll($tf, $ola);
        $html = $this->render('@Antispam/User/index.html.twig', [
            'users' => [$ola, TwoFactorFixtures::user(User::ROLE_ADMIN, 9, 'adam')],
            'env_admin' => 'admin', 'two_factor_required' => true, 'env_admin_2fa' => false,
        ], new InMemoryUser('admin', 'x', ['ROLE_ADMIN']), 'antispam_user_index');

        $this->assertStringContainsString('formaction="/users/2fa-reset/8"', $html);
        $this->assertStringNotContainsString('/users/2fa-reset/9', $html);
        $this->assertStringContainsString('brak (wymagana)', $html);
        $this->assertStringContainsString('action="/users/2fa-policy"', $html);
        $this->assertStringContainsString('nieustawiona', $html);
    }
}
