<?php

namespace AntispamBundle\Tests\Imap;

use AntispamBundle\Event\MessageEvent;
use AntispamBundle\Imap\ImapClient;
use AntispamBundle\Imap\SocketConnection;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\CryptoService;
use AntispamBundle\Services\ImapScanService;
use AntispamBundle\Services\MessageService;
use Ddeboer\Imap\Search\Date\Since;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * The ddeboer adapter (SocketConnection / SocketMailbox / SocketMessage)
 * against a real IMAP server. XOAUTH2 itself is covered by ImapClientTest;
 * here the server is a plain one with LOGIN, e.g. GreenMail:
 *
 *   docker run -d --name as-greenmail -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.hostname=0.0.0.0 -Dgreenmail.auth.disabled' \
 *       -p 33143:3143 greenmail/standalone:2.0.1
 *   ANTISPAM_TEST_IMAP=127.0.0.1:33143 vendor/bin/phpunit --filter SocketAdapterIntegrationTest
 *
 * Skipped without ANTISPAM_TEST_IMAP.
 */
class SocketAdapterIntegrationTest extends TestCase
{
    private SocketConnection $connection;
    private string $user;
    private string $tmp;

    protected function setUp(): void
    {
        $target = getenv('ANTISPAM_TEST_IMAP') ?: ($_SERVER['ANTISPAM_TEST_IMAP'] ?? '');
        if ($target === '' || !str_contains($target, ':')) {
            $this->markTestSkipped('Set ANTISPAM_TEST_IMAP=host:port of a plain test IMAP server (GreenMail).');
        }
        [$host, $port] = explode(':', $target, 2);
        $this->user = 'oauth-test-' . bin2hex(random_bytes(4)) . '@example.test';
        $client = new ImapClient(10, 5);
        $client->connect($host, (int)$port, ImapClient::ENC_NONE);
        $client->login($this->user, 'secret');
        $this->connection = new SocketConnection($client);
        $this->tmp = sys_get_temp_dir() . '/antispam-socket-' . bin2hex(random_bytes(4));
        mkdir($this->tmp);
    }

    protected function tearDown(): void
    {
        if (isset($this->connection)) {
            $this->connection->close();
        }
        if (isset($this->tmp) && is_dir($this->tmp)) {
            exec('rm -rf ' . escapeshellarg($this->tmp));
        }
    }

    private function message(string $from, string $subject, bool $attachment = false): string
    {
        $date = date('r');
        if (!$attachment) {
            return "From: $from\r\nTo: {$this->user}\r\nSubject: $subject\r\nDate: $date\r\nMessage-ID: <" . bin2hex(random_bytes(6)) . "@test>\r\n"
                . "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nZa=C5=BC=C3=B3=C5=82=C4=87 g=C4=99=C5=9Bl=C4=85 ja=C5=BA=C5=84\r\nhttp://example.test/link\r\n";
        }
        return "From: $from\r\nTo: {$this->user}\r\nSubject: $subject\r\nDate: $date\r\nMIME-Version: 1.0\r\n"
            . "Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>Faktura</p>\r\n"
            . "--b1\r\nContent-Type: application/octet-stream; name=\"faktura.exe\"\r\nContent-Disposition: attachment; filename=\"faktura.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . base64_encode("MZ\x90\x00fake") . "\r\n--b1--\r\n";
    }

    public function testListingReadingMovingAndFlags()
    {
        $inbox = $this->connection->getMailbox('INBOX');
        $inbox->addMessage($this->message('Jan Kowalski <jan@firma.pl>', 'Pierwsza'));
        $inbox->addMessage($this->message('"=?UTF-8?B?xYF1a2Fzeg==?=" <spam@evil.test>', '=?UTF-8?Q?Wygra=C5=82e=C5=9B?=', true));

        $status = $inbox->getStatus(\SA_MESSAGES | \SA_UIDVALIDITY | \SA_UIDNEXT);
        $this->assertSame(2, $status->messages);
        $this->assertGreaterThan(0, $status->uidvalidity);
        $uids = $inbox->getMessages()->getArrayCopy();
        $this->assertCount(2, $uids);
        $this->assertSame($uids, $inbox->getMessages(new Since(new \DateTimeImmutable('-2 days')))->getArrayCopy());
        $this->assertSame([max($uids)], $inbox->getMessageSequence((max($uids)) . ':*')->getArrayCopy());

        $first = $inbox->getMessage($uids[0]);
        $this->assertSame('jan@firma.pl', $first->getFrom()->getAddress());
        $this->assertSame('Jan Kowalski', $first->getFrom()->getName());
        $this->assertSame('Pierwsza', $first->getSubject());
        $this->assertStringContainsString('Zażółć gęślą jaźń', (string)$first->getBodyText());
        $this->assertNotNull($first->getDate());
        $this->assertNotEmpty($first->getHeaders()->get('maildate'), 'INTERNALDATE for the quarantine listing');
        $this->assertStringContainsString('Subject: Pierwsza', $first->getRawHeaders());
        $this->assertFalse($first->isSeen(), 'BODY.PEEK: reading does not mark as seen');

        $second = $inbox->getMessage($uids[1]);
        $this->assertSame('Łukasz', $second->getFrom()->getName());
        $this->assertSame('Wygrałeś', $second->getSubject());
        $this->assertSame('<p>Faktura</p>', trim((string)$second->getBodyHtml()));
        $attachments = $second->getAttachments();
        $this->assertCount(1, $attachments);
        $this->assertSame('faktura.exe', $attachments[0]->getFilename());
        $this->assertSame("MZ\x90\x00fake", $attachments[0]->getDecodedContent());

        $this->assertFalse($this->connection->hasMailbox('SPAM'));
        $spam = $this->connection->createMailbox('SPAM');
        $this->assertTrue($this->connection->hasMailbox('SPAM'));
        $second->move($spam);
        $this->connection->expunge();
        $this->assertSame([$uids[0]], $inbox->getMessages()->getArrayCopy());
        $this->assertCount(1, $spam->getMessages());
        $moved = $spam->getMessages()->current();
        $this->assertSame('spam@evil.test', $moved->getFrom()->getAddress());

        // Release back to INBOX (quarantine / SPAM release path).
        $moved->move($this->connection->getMailbox('INBOX'));
        $this->connection->expunge();
        $this->assertSame(0, $spam->count());
        $this->assertCount(2, $inbox->getMessages());

        $first->markAsSeen();
        $this->assertTrue($inbox->getMessage($uids[0])->isSeen());
        $first->delete();
        $this->connection->expunge();
        $this->assertCount(1, $inbox->getMessages());
    }

    /** The real ImapScanService::scan() on the adapter: cursor, move to SPAM, expunge. */
    public function testScanPipelineRunsOnTheAdapter()
    {
        $inbox = $this->connection->getMailbox('INBOX');
        $inbox->addMessage($this->message('jan@firma.pl', 'Dobra'));
        $inbox->addMessage($this->message('spam@evil.test', 'Zła'));
        $this->connection->createMailbox('SPAM');

        $ms = new MessageService($this->tmp . '/checked');
        $dispatcher = new EventDispatcher();
        $dispatcher->addListener('antispam.check.message', function (MessageEvent $e) {
            if ($e->getMessage()->getFrom()->getAddress() === 'spam@evil.test') {
                $e->getMessage()->move($e->getConnection()->getMailbox('SPAM'));
                $e->setSpam(true);
                $e->setDelete(true);
            }
        });
        $scan = new ImapScanService($dispatcher, $this->createMock(ConnectionService::class), $this->createMock(ConfigService::class),
            $this->createMock(CryptoService::class), $ms, null, $this->tmp . '/locks');

        $stats = $scan->scan($this->connection, $this->user, false, false, null, null, $cursor);
        $this->assertSame(2, $stats['checked'], json_encode($stats));
        $this->assertSame(1, $stats['moved_to_spam']);
        $this->assertSame([], $stats['errors']);
        $this->assertCount(1, $inbox->getMessages());
        $this->assertCount(1, $this->connection->getMailbox('SPAM')->getMessages());
        $this->assertNotNull($cursor);

        $inbox->addMessage($this->message('ola@firma.pl', 'Nowa'));
        $stats = $scan->scan($this->connection, $this->user, false, false, $cursor, null, $cursor);
        $this->assertSame(1, $stats['checked'], 'incremental: only the new UID');
    }
}
