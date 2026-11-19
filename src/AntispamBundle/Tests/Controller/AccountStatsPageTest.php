<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\AccountController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AccountDailyStat;
use AntispamBundle\Services\AccountStatsService;
use AntispamBundle\Tests\Support\JobsDatabase;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/** "Statystyki konta" renders for IMAP and SSH accounts (agent answer, agent error, no data). */
class AccountStatsPageTest extends KernelTestCase
{
    private function render(Account $account, ?array $agent, JobsDatabase $db): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/account/stats/' . $account->getId());
        $request->attributes->set('_route', 'antispam_account_stats');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        $admin = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($admin, 'main', $admin->getRoles()));

        $stats = new AccountStatsService($db->em);
        $since = AccountStatsService::since(30);
        return $c->get('twig')->render('@Antispam/Account/stats.html.twig', [
            'account' => $account, 'days' => 30, 'periods' => AccountController::STATS_PERIODS, 'kinds' => AccountDailyStat::KINDS,
            'totals' => $stats->totals((int)$account->getId(), $since), 'daily' => $stats->daily((int)$account->getId(), 30),
            'log' => $stats->scoreLog((string)$account->getEmail(), $since), 'plugin_reports' => ['spam' => 2],
            'agent' => $agent, 'last_scan' => null, 'last_rescan' => null,
        ]);
    }

    private function account(JobsDatabase $db, string $type): Account
    {
        $a = (new Account())->setName('Jan')->setEmail('jan@firma.pl')->setConnectionType($type);
        $db->em->persist($a);
        $db->em->flush();
        return $a;
    }

    public function testImapAccount()
    {
        $db = new JobsDatabase();
        $a = $this->account($db, 'imap');
        (new AccountStatsService($db->em))->record($a, AccountDailyStat::KIND_SCAN, ['checked' => 40, 'moved_to_spam' => 3, 'quarantined' => 2, 'whitelisted' => 5]);
        $html = $this->render($a, null, $db);
        $this->assertStringContainsString('Przeniesione do SPAM', $html);
        $this->assertStringContainsString('skany nowej poczty', $html);
        $this->assertStringContainsString('Zgłoszenia z wtyczki', $html);
        $this->assertStringContainsString('pełny dziennik ocen', $html);
        $this->assertStringContainsString('7,5%', $html);
    }

    public function testSshAccount()
    {
        $db = new JobsDatabase();
        $a = $this->account($db, 'ssh');
        $this->assertStringContainsString('Pobierz statystyki z agenta', $this->render($a, null, $db));
        $this->assertStringContainsString('wdróż go ponownie', $this->render($a, ['success' => false, 'error' => 'Agent na serwerze nie obsługuje polecenia "stats"'], $db));
        $html = $this->render($a, ['success' => true, 'total' => 3, 'decisions' => ['spam' => 2, 'ham' => 1], 'daily' => [], 'senders' => ['a@spam.pl' => 2],
            'domains' => ['spam.pl' => 2], 'rules' => ['email_blacklist:a@spam.pl (exact)' => 2], 'categories' => ['email_blacklist' => 2],
            'recent' => [['sender' => 'a@spam.pl', 'subject' => 'kup <b>', 'score' => 10, 'decision' => 'spam', 'scored_at' => '2026-11-19T10:00:00+01:00']],
            'scans' => ['runs' => 4, 'last' => '2026-11-19 10:00:00'], 'retention_days' => 180, 'first_entry' => null, 'sampled' => false], $db);
        $this->assertStringContainsString('czarna lista (adres)', $html);
        $this->assertStringContainsString('kup &lt;b&gt;', $html);
        $this->assertStringContainsString('przechowuje 180 dni', $html);
    }
}
