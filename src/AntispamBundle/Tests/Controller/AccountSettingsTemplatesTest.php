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

    public function testListAndEditShowTheRescan()
    {
        $done = self::account(1)->setAutoRescan(true)->setRescanWeekday(3)->setRescanHour(4);
        $done->markRescanned(['checked' => 120, 'moved_to_spam' => 7, 'quarantined' => 2, 'whitelisted' => 1, 'job' => 42], new \DateTimeImmutable('2026-10-28 04:10'));
        $failed = self::account(2);
        $failed->markRescanned(['error' => 'Agent na serwerze nie obsługuje polecenia "rescan" - wdróż go ponownie']);
        $html = $this->render('@Antispam/Account/index.html.twig', ['accounts' => [$done, $failed, self::account(3)]]);

        $this->assertSame(3, substr_count($html, 'Przeskanuj całą skrzynkę ponownie"'), 'button on every account');
        $this->assertStringContainsString('<b>2026-10-28 04:10</b>', $html);
        $this->assertStringContainsString('co tydzień: środa 04:00', $html);
        $this->assertStringContainsString('Do spamu <b>7</b>', $html);
        $this->assertStringContainsString('zadanie #42', $html);
        $this->assertStringContainsString('wdróż go ponownie', $html);
        $this->assertSame(2, substr_count($html, 'Ponowny skan całej skrzynki:'), 'no rescan row for an account that never had one');

        $html = $this->render('@Antispam/Account/edit.html.twig', [
            'account' => $done,
            'global_settings' => new MailboxSettings(10, 5, true, false, true, null, null),
            'imap_tls' => \AntispamBundle\Services\ImapFlags::parse('/imap/ssl'),
            'imap_flags' => '/imap/ssl',
            'next_rescan' => new \DateTimeImmutable('2026-11-04 04:00'),
        ]);
        $this->assertStringContainsString('name="account[auto_rescan]" value="1" checked', $html);
        $this->assertStringContainsString('<option value="3" selected>środa</option>', $html);
        $this->assertStringContainsString('name="account[rescan_hour]" value="4"', $html);
        $this->assertStringContainsString('Najbliższy: <strong>2026-11-04 04:00</strong>', $html);
        $this->assertStringContainsString('/account/rescan/1', $html);
    }

    public function testRescanJobResult()
    {
        $html = $this->render('@Antispam/Job/result/account.rescan.html.twig', ['result' => ['success' => true, 'messages' => [], 'scan_result' => [
            'total' => 300, 'checked' => 300, 'whitelisted' => 4, 'blacklisted' => 2, 'moved_to_spam' => 5, 'quarantined' => 3, 'errors' => ['UID 7: boom'], 'trigger' => 'schedule',
        ]]]);
        $this->assertStringContainsString('Ponowny skan całej skrzynki zakończony', $html);
        $this->assertStringContainsString('<th>Przeniesione do kwarantanny</th><td>3</td>', $html);
        $this->assertStringContainsString('harmonogram (co tydzień)', $html);
        $this->assertStringContainsString('UID 7: boom', $html);

        $html = $this->render('@Antispam/Job/result/account.rescan.html.twig', ['result' => ['checked' => 10, 'remaining' => 5]]);
        $this->assertStringContainsString('Ponowny skan przerwany', $html);
    }
}
