<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\InboxService;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Exception\CreateMailboxException;
use Ddeboer\Imap\MailboxInterface;
use PHPUnit\Framework\TestCase;

/** SPAM / QUARANTINE folder lookup: the mailbox's own folder before creating one. */
class InboxServiceFolderTest extends TestCase
{
    public function testFindExisting()
    {
        $this->assertSame('Spam', InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX', 'Wysłane', 'Spam']));
        $this->assertSame('INBOX.Spam', InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX', 'INBOX.Spam', 'INBOX.Stare.spam']));
        $this->assertSame('Spam', InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX.Spam', 'Spam']));
        $this->assertSame('[Gmail]/Spam', InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX', '[Gmail]/Spam']));
        $this->assertSame('Junk', InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX', 'Junk']));
        $this->assertSame('Spam', InboxService::findExisting(InboxService::KIND_SPAM, ['Junk', 'Spam']));
        $this->assertNull(InboxService::findExisting(InboxService::KIND_SPAM, ['INBOX', 'Spamerzy-archiwum']));
        $this->assertSame('Kwarantanna', InboxService::findExisting(InboxService::KIND_QUARANTINE, ['INBOX', 'Spam', 'Kwarantanna']));
        $this->assertNull(InboxService::findExisting(InboxService::KIND_QUARANTINE, ['INBOX', 'Spam']));
    }

    private function connection(array &$names, array $refused = []): ConnectionInterface
    {
        $c = $this->createMock(ConnectionInterface::class);
        $box = function (string $name) {
            $m = $this->createMock(MailboxInterface::class);
            $m->method('getName')->willReturn($name);
            $m->method('getDelimiter')->willReturn('.');
            return $m;
        };
        $c->method('hasMailbox')->willReturnCallback(function ($n) use (&$names) { return in_array($n, $names, true); });
        $c->method('getMailboxes')->willReturnCallback(function () use (&$names, $box) { return array_combine($names, array_map($box, $names)); });
        $c->method('getMailbox')->willReturnCallback(fn ($n) => $box($n));
        $c->method('createMailbox')->willReturnCallback(function ($n) use (&$names, $refused, $box) {
            if (in_array($n, $refused, true)) {
                throw new CreateMailboxException('Can not create "' . $n . '" mailbox');
            }
            $names[] = $n;
            return $box($n);
        });
        return $c;
    }

    public function testUsesTheMailboxSpamFolderInsteadOfCreating()
    {
        $names = ['INBOX', 'Spam', 'Kosz'];
        $c = $this->connection($names, ['SPAM']);
        $inbox = new InboxService($this->createMock(ConnectionService::class));
        $this->assertSame('Spam', $inbox->getSpamFolderName($c));
        $this->assertSame('Spam', $inbox->getSpamFolder($c)->getName());
        $this->assertSame(['INBOX', 'Spam', 'Kosz'], $names);
        $this->assertSame('SPAM', $inbox->getSpamFolderName());
    }

    public function testCreatesUnderInboxWhenTopLevelIsRefused()
    {
        $names = ['INBOX'];
        $c = $this->connection($names, ['QUARANTINE']);
        $inbox = new InboxService($this->createMock(ConnectionService::class));
        $this->assertSame('INBOX.QUARANTINE', $inbox->getQuarantineFolder($c)->getName());
        $this->assertSame('INBOX.QUARANTINE', $inbox->getQuarantineFolderName($c));
        $this->assertSame('SPAM', $inbox->getSpamFolder($c)->getName());
    }

    public function testClearErrorWhenNothingCanBeCreated()
    {
        $names = ['INBOX'];
        $c = $this->connection($names, ['SPAM', 'INBOX.SPAM']);
        $inbox = new InboxService($this->createMock(ConnectionService::class));
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/nie pozwala utworzyć folderu „SPAM”/');
        $inbox->getSpamFolder($c);
    }
}
