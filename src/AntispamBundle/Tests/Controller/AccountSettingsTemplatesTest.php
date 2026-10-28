<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\MailboxSettings;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/** "Ustawienia skrzynki" on the account edit page and the override badge on the list. */
class AccountSettingsTemplatesTest extends KernelTestCase
{
    private function render(string $template, array $vars): string
    {
        self::bootKernel();
        $request = Request::create('/');
        $request->setSession(new Session(new MockArraySessionStorage()));
        self::getContainer()->get('request_stack')->push($request);
        return self::getContainer()->get('twig')->render($template, $vars);
    }

    private static function account(int $id): Account
    {
        $a = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType(Account::CONNECTION_IMAP)->setImapFlags('/imap/ssl');
        (new \ReflectionProperty(Account::class, 'id'))->setValue($a, $id);
        return $a;
    }

    public function testEditShowsInheritedValuesAndOverrides()
    {
        $account = self::account(3)->setSpamThreshold(6)->setScoringEnabled(false)->setDigestRecipient('szef@firma.pl');
        $html = $this->render('@Antispam/Account/edit.html.twig', [
            'account' => $account,
            'global_settings' => new MailboxSettings(10, 5, true, false, true, null, null),
            'imap_tls' => \AntispamBundle\Services\ImapFlags::parse('/imap/ssl'),
            'imap_flags' => '/imap/ssl',
        ]);

        $this->assertStringContainsString('Ustawienia skrzynki', $html);
        $this->assertStringContainsString('name="account[spam_threshold]" value="6" placeholder="dziedzicz (10)"', $html);
        $this->assertStringContainsString('name="account[quarantine_threshold]" value="" placeholder="dziedzicz (5)"', $html);
        $this->assertMatchesRegularExpression('~<option value="0" selected>wyłączona~', $html);
        $this->assertStringContainsString('<option value="" selected>dziedzicz (włączony)</option>', $html);
        $this->assertStringContainsString('value="szef@firma.pl" placeholder="dziedzicz (jan@firma.pl)"', $html);
        $this->assertStringContainsString('zawsze używa ustawień globalnych', $html);
    }

    public function testListMarksMailboxesWithOverrides()
    {
        $html = $this->render('@Antispam/Account/index.html.twig', ['accounts' => [self::account(1)->setDigestHour(9), self::account(2)]]);
        $this->assertSame(1, substr_count($html, '>własne ustawienia</a>'));
        $this->assertStringContainsString('title="Własne ustawienia skrzynki: godzina raportu"', $html);
    }
}
