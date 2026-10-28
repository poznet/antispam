<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Event\MessageEvent;
use AntispamBundle\EventListener\Message\CheckBlacklist;
use AntispamBundle\EventListener\Message\CheckEmailBlacklist;
use AntispamBundle\EventListener\Message\CheckEmailWhitelist;
use AntispamBundle\EventListener\Message\CheckWhitelist;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SshService;
use AntispamBundle\Tests\Support\RuleFixtures;
use Ddeboer\Imap\Message\Headers;
use Ddeboer\Imap\MessageInterface;
use PHPUnit\Framework\TestCase;

/**
 * A rule owned by '*' (Wszystkie skrzynki) must reach every consumer, while a
 * rule owned by another mailbox must not.
 */
class GlobalRulesConsumersTest extends TestCase
{
    private RuleFixtures $db;

    protected function setUp(): void
    {
        $this->db = new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl', 'anna@firma.pl']);
        $this->db->add((new Blacklist())->setEmail('*')->setHost('global-spam.example')->setScore(12));
        $this->db->add((new Blacklist())->setEmail('anna@firma.pl')->setHost('anna-only.example')->setScore(12));
        $this->db->add((new EmailBlacklist())->setEmail('*')->setBlacklistemail('bad@global.example')->setScore(9));
        $this->db->add((new Whitelist())->setEmail('*')->setHost('partner.example'));
        $this->db->add((new EmailWhitelist())->setEmail('*')->setWhitelistemail('boss@partner2.example'));
    }

    private function event(string $mailbox, string $sender): MessageEvent
    {
        [$local, $host] = explode('@', $sender);
        $msg = $this->createMock(MessageInterface::class);
        $msg->method('getHeaders')->willReturn(new Headers((object)[
            'sender' => [(object)['mailbox' => $local, 'host' => $host]],
        ]));
        return new MessageEvent($msg, $mailbox);
    }

    private function scoring(): ScoringService
    {
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $scoring->method('exportAgentSettings')->willReturn([]);
        return $scoring;
    }

    public function testDomainBlacklistListenerAppliesGlobalRuleToAnyMailbox()
    {
        $listener = new CheckBlacklist($this->db->em, $this->createMock(MessageService::class), $this->scoring());

        $event = $this->event('jan@firma.pl', 'x@global-spam.example');
        $listener->check($event);
        $this->assertTrue($event->isBlacklist());
        $this->assertSame(12, $event->getSpamscore());

        $other = $this->event('jan@firma.pl', 'x@anna-only.example');
        $listener->check($other);
        $this->assertFalse((bool)$other->isBlacklist(), "anna's rule must not apply to jan");

        $this->assertSame(['email' => ['jan@firma.pl', '*']], $this->db->repos[Blacklist::class]->queries[0]);
    }

    public function testEmailBlacklistListenerAppliesGlobalRule()
    {
        $listener = new CheckEmailBlacklist($this->db->em, $this->createMock(MessageService::class), $this->scoring());
        $event = $this->event('biuro@firma.pl', 'bad@global.example');
        $listener->check($event);
        $this->assertTrue($event->isBlacklist());
        $this->assertSame(9, $event->getSpamscore());
    }

    public function testWhitelistListenersApplyGlobalRules()
    {
        $event = $this->event('anna@firma.pl', 'someone@partner.example');
        (new CheckWhitelist($this->db->em, $this->createMock(MessageService::class)))->check($event);
        $this->assertTrue($event->isWhitelist());

        $event = $this->event('anna@firma.pl', 'boss@partner2.example');
        (new CheckEmailWhitelist($this->db->em, $this->createMock(MessageService::class)))->check($event);
        $this->assertTrue($event->isWhitelist());
    }

    public function testAgentExportContainsOwnAndGlobalRulesOnly()
    {
        $rules = (new AgentRulesExporter($this->db->em, $this->scoring()))->export('jan@firma.pl');

        $this->assertSame(['global-spam.example'], array_column($rules['blacklist'], 'host'));
        $this->assertSame(['bad@global.example'], array_column($rules['email_blacklist'], 'blacklistemail'));
        $this->assertSame(['partner.example'], array_column($rules['whitelist'], 'host'));
        $this->assertSame(['boss@partner2.example'], array_column($rules['email_whitelist'], 'whitelistemail'));

        $anna = (new AgentRulesExporter($this->db->em, $this->scoring()))->export('anna@firma.pl');
        $this->assertSame(['global-spam.example', 'anna-only.example'], array_column($anna['blacklist'], 'host'));
    }

    public function testRetroactivePassOfGlobalRuleVisitsEveryAccount()
    {
        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(false);
        $imapScan = $this->createMock(ImapScanService::class);
        $imapScan->method('isLegacyConfigured')->willReturn(false);
        $service = new RetroactiveSpamService(
            $this->db->em, $scoring, $imapScan,
            $this->createMock(ConnectionService::class), $this->db->config,
            $this->createMock(InboxService::class), $this->createMock(SshService::class),
            $this->createMock(AgentRulesExporter::class),
        );
        $accounts = $this->db->repos[Account::class];

        $service->applyRule((new Blacklist())->setEmail('*')->setHost('global-spam.example')->setScore(12));
        $this->assertSame([], end($accounts->queries), 'global rule: every account');

        $service->applyRule((new Blacklist())->setEmail('anna@firma.pl')->setHost('anna-only.example')->setScore(12));
        $this->assertSame(['email' => 'anna@firma.pl'], end($accounts->queries));
    }
}
