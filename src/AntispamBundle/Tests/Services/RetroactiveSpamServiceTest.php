<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\AgentRulesExporter;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\InboxService;
use AntispamBundle\Services\PatternMatcher;
use AntispamBundle\Services\RetroactiveSpamService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SshService;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\ImapResourceInterface;
use Ddeboer\Imap\MailboxInterface;
use Ddeboer\Imap\Message\EmailAddress;
use Ddeboer\Imap\MessageInterface;
use Ddeboer\Imap\MessageIterator;
use Ddeboer\Imap\Search\ConditionInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use PHPUnit\Framework\TestCase;

class RetroactiveSpamServiceTest extends TestCase
{
    /** @var array<int, string> uid => From address */
    private $inbox = [];
    private $search;
    private $moved = [];
    private $broken = [];

    private function applyRule($rule)
    {
        $this->moved = [];
        $resource = $this->createMock(ImapResourceInterface::class);
        $mailbox = $this->createMock(MailboxInterface::class);
        $mailbox->method('getMessages')->willReturnCallback(function (ConditionInterface $c) use ($resource) {
            $this->search = $c->toString();
            return new MessageIterator($resource, array_keys($this->inbox));
        });
        $mailbox->method('getMessage')->willReturnCallback(function ($uid) {
            $m = $this->createMock(MessageInterface::class);
            if (in_array($uid, $this->broken, true)) {
                $m->method('getFrom')->willThrowException(new \RuntimeException('gone'));
                return $m;
            }
            [$box, $host] = explode('@', $this->inbox[$uid]);
            $m->method('getFrom')->willReturn(new EmailAddress($box, $host));
            $m->method('move')->willReturnCallback(function () use ($uid) { $this->moved[] = $uid; });
            return $m;
        });
        $connection = $this->createMock(ConnectionInterface::class);
        $connection->method('getMailbox')->willReturn($mailbox);

        $account = (new Account())->setEmail('box@firma.pl');
        $accounts = $this->createMock(EntityRepository::class);
        $accounts->method('findBy')->willReturnCallback(function ($criteria) use ($account) {
            return isset($criteria['email']) && count($criteria) === 1 && $criteria['email'] === 'box@firma.pl' ? [$account] : [];
        });
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(function ($class) use ($accounts) {
            if ($class === Account::class) {
                return $accounts;
            }
            $empty = $this->createMock(EntityRepository::class);
            $empty->method('findBy')->willReturn([]);
            return $empty;
        });

        $scoring = $this->createMock(ScoringService::class);
        $scoring->method('isScoringEnabled')->willReturn(true);
        $scoring->method('getSpamThreshold')->willReturn(10);
        $imap = $this->createMock(ImapScanService::class);
        $imap->method('connect')->willReturn($connection);
        $inbox = $this->createMock(InboxService::class);
        $inbox->method('getSpamFolder')->willReturn($this->createMock(MailboxInterface::class));

        $service = new RetroactiveSpamService($em, $scoring, $imap, $this->createMock(ConnectionService::class),
            $this->createMock(ConfigService::class), $inbox, $this->createMock(SshService::class), $this->createMock(AgentRulesExporter::class));
        return $service->applyRule($rule);
    }

    public function testExactRuleUsesDateWindowAndServerSideFrom()
    {
        $this->inbox = [1 => 'a@spam.pl', 2 => 'b@ok.pl', 3 => 'c@spam.pl'];
        $rule = (new Blacklist())->setEmail('box@firma.pl')->setHost('spam.pl')->setScore(10);

        $result = $this->applyRule($rule);

        $this->assertMatchesRegularExpression('/^SINCE "[^"]+" FROM "@spam\.pl"$/', $this->search);
        $this->assertSame([3, 1], $this->moved, 'newest first');
        $this->assertSame(2, $result['moved']);
    }

    public function testValueThatCannotBeQuotedIsMatchedClientSide()
    {
        $this->inbox = [1 => 'x@evil.pl'];
        $rule = (new EmailBlacklist())->setEmail('box@firma.pl')->setBlacklistemail('a"b@evil.pl')->setScore(10);

        $this->applyRule($rule);
        $this->assertMatchesRegularExpression('/^SINCE "[^"]+"$/', $this->search);
    }

    public function testOneBadMessageDoesNotStopThePass()
    {
        $this->inbox = [1 => 'a@spam.pl', 2 => 'b@spam.pl', 3 => 'c@spam.pl'];
        $this->broken = [2];
        $rule = (new Blacklist())->setEmail('box@firma.pl')->setHost('*.pl')->setPatternType(PatternMatcher::WILDCARD)->setScore(10);

        $result = $this->applyRule($rule);

        $this->assertSame([3, 1], $this->moved);
        $this->assertCount(1, $result['errors']);
        $this->assertStringContainsString('UID 2', $result['errors'][0]);
    }
}
