<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Entity\User;
use AntispamBundle\Tests\Support\TwoFactorFixtures;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Bulk delete buttons on both quarantine pages (CSP-safe data-confirm naming
 * the mailbox and the count, CSRF, POST) and the user-area job page.
 */
class QuarantinePurgeTemplatesTest extends KernelTestCase
{
    private function render(string $template, array $vars, object $user, string $route): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/x');
        $request->attributes->set('_route', $route);
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        return $c->get('twig')->render($template, $vars);
    }

    private static function item(string $id, bool $risky): array
    {
        return ['id' => $id, 'from' => 'a@b.pl', 'from_name' => '', 'subject' => 'S', 'date' => null, 'score' => 6, 'labels' => [], 'high_risk' => $risky, 'uidvalidity' => 1];
    }

    private static function mailboxes(): array
    {
        return [
            ['key' => 'imap-5', 'label' => 'Jan (jan@firma.pl)', 'account_email' => 'jan@firma.pl', 'error' => null,
                'items' => [self::item('1', true), self::item('2', false), self::item('3', true)], 'high_risk_count' => 2, 'capped' => false],
            ['key' => 'ssh-6', 'label' => 'Ola (ola@firma.pl)', 'account_email' => 'ola@firma.pl', 'error' => null,
                'items' => [self::item('x', false)], 'high_risk_count' => 0, 'capped' => true],
            ['key' => 'ssh-7', 'label' => 'Pusta', 'account_email' => 'p@firma.pl', 'error' => null, 'items' => [], 'high_risk_count' => 0, 'capped' => false],
        ];
    }

    public function testAdminQuarantineButtons()
    {
        $html = $this->render('@Antispam/Spambox/quarantine.html.twig', ['mailboxes' => self::mailboxes(), 'logs' => [], 'locations' => []],
            new InMemoryUser('admin', null, ['ROLE_ADMIN']), 'antispam_spambox_quarantine');

        $this->assertSame(2, substr_count($html, 'value="all"'), 'one "Usuń wszystko" per non-empty mailbox');
        $this->assertSame(1, substr_count($html, 'name="mode" value="high_risk"'), 'high-risk button only where there are high-risk messages');
        $this->assertStringContainsString('action="/spambox/quarantine/purge"', $html);
        $this->assertStringContainsString('action="/spambox/quarantine/purge-all"', $html);
        $this->assertStringContainsString('Usuń wszystkie wysokiego ryzyka (wszystkie skrzynki)', $html);
        $this->assertStringContainsString('data-confirm="Trwale usunąć wiadomości wysokiego ryzyka z kwarantanny skrzynki Jan (jan@firma.pl)? Na liście: 2.', $html);
        $this->assertStringContainsString('data-confirm="Trwale usunąć WSZYSTKIE wiadomości z kwarantanny skrzynki Ola (ola@firma.pl)? Na liście: 1 (lista pokazuje tylko pierwsze 1', $html);
        $this->assertStringContainsString('Na listach: 2.', $html);
        $this->assertStringNotContainsString('onclick', $html);
    }

    public function testUserQuarantineButtonsAndJobPage()
    {
        $user = TwoFactorFixtures::user(User::ROLE_USER);
        $html = $this->render('@Antispam/My/quarantine.html.twig', ['mailboxes' => [self::mailboxes()[0]]], $user, 'antispam_my_quarantine');
        $this->assertStringContainsString('action="/my/quarantine/purge"', $html);
        $this->assertStringContainsString('Usuń wszystko z kwarantanny', $html);
        $this->assertStringContainsString('Usuń wszystkie wysokiego ryzyka', $html);
        $this->assertStringNotContainsString('wszystkie skrzynki', $html, 'no global button for users');

        $job = new BackgroundJob(BackgroundJob::TYPE_QUARANTINE_PURGE);
        foreach (['id' => 3, 'status' => 'done', 'label' => 'Usuń wszystko z kwarantanny: Jan', 'mailbox' => 'jan@firma.pl', 'createdAt' => new \DateTime(), 'finishedAt' => new \DateTime()] as $p => $v) {
            (new \ReflectionProperty(BackgroundJob::class, $p))->setValue($job, $v);
        }
        $result = ['total' => 5, 'deleted' => 4, 'skipped' => 0, 'failed' => 1, 'errors' => ['UID 9: imap.firma.pl timeout'], 'mode' => 'all', 'shown' => 5];
        $page = $this->render('@Antispam/My/job.html.twig', ['job' => $job, 'result' => $result, 'is_admin' => false], $user, 'antispam_my_job_show');
        $this->assertStringContainsString('Usunięte trwale', $page);
        $this->assertStringContainsString('<strong>4</strong>', $page);
        $this->assertStringNotContainsString('imap.firma.pl', $page, 'raw errors stay in the admin area');
        $this->assertStringContainsString('href="/my/quarantine"', $page);
        $this->assertStringNotContainsString('"/jobs/', $page, 'no link to the admin job pages');
    }
}
