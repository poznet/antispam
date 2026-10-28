<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\PluginReport;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\SpamSignalService;
use AntispamBundle\Tests\Services\Bayes\BayesTestCase;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Report scopes (Thunderbird plugin 1.3.0): a report_only report - a message
 * from another Thunderbird account without its own login - feeds the shared
 * fingerprints but teaches nothing to the mailbox whose token was used.
 */
class PluginReportScopeTest extends BayesTestCase
{
    private const RAW = "From: Spammer <spam@evil.top>\r\nSubject: Buy now\r\nMessage-ID: <x1@evil.top>\r\n\r\nCheap pills, cheap pills, cheap pills\r\n";

    private function plugin(?SpamSignalService $feed = null): PluginService
    {
        return new PluginService($this->em, $this->createMock(CacheItemPoolInterface::class), $feed ?? $this->createMock(SpamSignalService::class), 'secret', $this->config, null, $this->bayes());
    }

    public function testScopeFromRequest()
    {
        $this->assertSame(PluginService::SCOPE_MAILBOX, PluginService::scopeFrom([]), 'no field: behaviour of older plugins');
        $this->assertSame(PluginService::SCOPE_MAILBOX, PluginService::scopeFrom(null));
        $this->assertSame(PluginService::SCOPE_MAILBOX, PluginService::scopeFrom(['scope' => '']));
        $this->assertSame(PluginService::SCOPE_MAILBOX, PluginService::scopeFrom(['scope' => 'mailbox']));
        $this->assertSame(PluginService::SCOPE_REPORT_ONLY, PluginService::scopeFrom(['scope' => 'report_only']));
        $this->assertNull(PluginService::scopeFrom(['scope' => 'everything']));
        $this->assertNull(PluginService::scopeFrom(['scope' => ['report_only']]));
    }

    public function testReportedFromKeepsValidAddressesOnly()
    {
        $this->assertNull(PluginService::reportedFromValue(null));
        $this->assertNull(PluginService::reportedFromValue(''));
        $this->assertNull(PluginService::reportedFromValue('not an address'));
        $this->assertNull(PluginService::reportedFromValue(['x' => ['nested']]));
        $this->assertSame('anna@firma.pl', PluginService::reportedFromValue(' Anna@Firma.PL '));
        $this->assertSame('a@x.pl, b@x.pl', PluginService::reportedFromValue(['a@x.pl', 'B@x.pl', 'a@x.pl', '<script>', 42]));
        $this->assertSame('a@x.pl, b@x.pl', PluginService::reportedFromValue('a@x.pl, b@x.pl'));
        $many = array_map(fn ($i) => "u$i@x.pl", range(1, 10));
        $this->assertCount(PluginService::MAX_REPORTED_FROM, explode(', ', PluginService::reportedFromValue($many)));
        $long = [str_repeat('a', 60) . '@' . str_repeat('b', 60) . '.pl', str_repeat('c', 60) . '@' . str_repeat('d', 60) . '.pl', str_repeat('e', 60) . '@x.pl'];
        $this->assertLessThanOrEqual(255, mb_strlen(PluginService::reportedFromValue($long)));
    }

    public function testReportOnlySpamFeedsFingerprintsButLearnsNoRules()
    {
        $account = $this->account('jan@firma.pl');
        $feed = $this->createMock(SpamSignalService::class);
        $feed->method('signalsFor')->willReturn([['type' => 'sender', 'hash' => 'h']]);
        $feed->expects($this->once())->method('record')->willReturn(1);

        $result = $this->plugin($feed)->learn(self::RAW, PluginService::VERDICT_SPAM, $account, '1.2.3.4', 'plugin', PluginService::SCOPE_REPORT_ONLY, 'anna@inna.pl');

        $this->assertSame(PluginService::SCOPE_REPORT_ONLY, $result['scope']);
        $this->assertSame(1, $result['signals']);
        $this->assertSame([], $result['rules']);
        $this->assertArrayNotHasKey('bayes', $result, 'no Bayes training for a foreign account');
        $this->assertSame(0, $this->em->getRepository(EmailBlacklist::class)->count([]));
        $this->assertSame(0, $this->bayes()->stats()['spam']);

        $log = $this->em->getRepository(PluginReport::class)->findAll();
        $this->assertCount(1, $log);
        $this->assertSame('jan@firma.pl', $log[0]->getAccountEmail(), 'the authenticating mailbox is still the reporter');
        $this->assertSame('anna@inna.pl', $log[0]->getReportedFrom());
    }

    public function testMailboxScopeKeepsTheOldBehaviour()
    {
        $account = $this->account('jan@firma.pl');
        $ham = (new EmailWhitelist())->setEmail('jan@firma.pl')->setWhitelistemail('spam@evil.top')->setPatternType('exact')->setCounter(0);
        $this->em->persist($ham);
        $this->em->flush();

        $result = $this->plugin()->learn(self::RAW, PluginService::VERDICT_SPAM, $account);

        $this->assertSame(PluginService::SCOPE_MAILBOX, $result['scope']);
        $this->assertSame(['email_whitelist_removed:spam@evil.top', 'email_blacklist_added:spam@evil.top'], $result['rules']);
        $this->assertTrue($result['bayes']);
        $this->assertSame(1, $this->em->getRepository(EmailBlacklist::class)->count(['email' => 'jan@firma.pl']));
        $this->assertNull($this->em->getRepository(PluginReport::class)->findAll()[0]->getReportedFrom());
    }
}
