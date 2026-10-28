<?php

namespace AntispamBundle\Tests\Repository;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Entity\User;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Tests\Security\MailboxAccessTest;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/**
 * The score log query a ROLE_USER runs must never return rows of another
 * mailbox - not even when the request asks for one by e-mail.
 */
class ScoreLogScopeTest extends TestCase
{
    private EntityManager $em;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema([$this->em->getClassMetadata(SpamScoreLog::class)]);

        foreach (['jan@firma.pl' => 'spam', 'jan@firma.pl ' => 'quarantine', 'boss@firma.pl' => 'spam', 'other@x.pl' => 'ham'] as $email => $decision) {
            $this->em->persist((new SpamScoreLog())->setAccountEmail(trim($email))->setSender('s@x.pl')->setSubject('t ' . $email)->setScore(9)->setDecision($decision));
        }
        $this->em->persist((new SpamScoreLog())->setAccountEmail(null)->setSender('s@x.pl')->setSubject('no account')->setScore(1)->setDecision('ham'));
        $this->em->flush();
    }

    private function emails(array $filters): array
    {
        $items = $this->em->getRepository(SpamScoreLog::class)->search($filters)['items'];
        $emails = array_map(fn(SpamScoreLog $l) => $l->getAccountEmail(), $items);
        sort($emails);
        return $emails;
    }

    public function testUserSeesOnlyOwnMailboxRows()
    {
        $access = new MailboxAccess();
        $user = MailboxAccessTest::user(User::ROLE_USER, [MailboxAccessTest::account(1, 'jan@firma.pl')]);

        $this->assertSame(['jan@firma.pl', 'jan@firma.pl'], $this->emails($access->scopeScoreLogFilters($user, [])));
        $this->assertSame(['jan@firma.pl'], $this->emails($access->scopeScoreLogFilters($user, ['decision' => 'spam'])));
    }

    public function testRequestedForeignAccountDoesNotLeak()
    {
        $access = new MailboxAccess();
        $user = MailboxAccessTest::user(User::ROLE_USER, [MailboxAccessTest::account(1, 'jan@firma.pl')]);

        $rows = $this->emails($access->scopeScoreLogFilters($user, ['account' => 'boss@firma.pl']));
        $this->assertNotContains('boss@firma.pl', $rows);
        $this->assertNotContains('other@x.pl', $rows);
        $this->assertNotContains(null, $rows);
    }

    public function testUserWithoutMailboxesGetsNoRows()
    {
        $user = MailboxAccessTest::user(User::ROLE_USER, []);
        $this->assertSame([], $this->emails((new MailboxAccess())->scopeScoreLogFilters($user, [])));
    }

    public function testAdminSeesEverything()
    {
        $admin = MailboxAccessTest::user(User::ROLE_ADMIN, []);
        $this->assertCount(5, $this->emails((new MailboxAccess())->scopeScoreLogFilters($admin, [])));
    }
}
