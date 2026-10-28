<?php

namespace AntispamBundle\Tests\Imap;

use AntispamBundle\Imap\ImapClient;
use AntispamBundle\Imap\ImapException;
use AntispamBundle\Imap\SocketConnection;
use PHPUnit\Framework\TestCase;

/**
 * Socket IMAP client against a scripted server (one end of a socket pair):
 * the server answers are written up front, tags are predictable (A0001...),
 * and the commands the client sent are read back at the end.
 */
class ImapClientTest extends TestCase
{
    /** @var resource */
    private $server;

    private function client(string $script): ImapClient
    {
        [$a, $b] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $this->server = $b;
        fwrite($b, str_replace("\n", "\r\n", $script));
        return ImapClient::fromStream($a, 2);
    }

    /** @return string[] command lines the client sent */
    private function sent(): array
    {
        stream_set_blocking($this->server, false);
        $data = (string)stream_get_contents($this->server);
        return array_values(array_filter(explode("\r\n", $data), 'strlen'));
    }

    public function testXoauth2MatchesTheMicrosoftDocumentationExample()
    {
        $this->assertSame(
            'dXNlcj10ZXN0QGNvbnRvc28ub25taWNyb3NvZnQuY29tAWF1dGg9QmVhcmVyIEV3QkFBbDNCQUFVRkZwVUFvN0ozVmUwYmpMQldaV0NjbFJDM0VvQUEBAQ==',
            ImapClient::xoauth2('test@contoso.onmicrosoft.com', 'EwBAAl3BAAUFFpUAo7J3Ve0bjLBWZWCclRC3EoAA')
        );
        $this->assertSame("user=a@b.pl\x01auth=Bearer tok\x01\x01", base64_decode(ImapClient::xoauth2('a@b.pl', 'tok')));
    }

    public function testXoauth2RejectsControlCharacters()
    {
        $this->expectException(\InvalidArgumentException::class);
        ImapClient::xoauth2("a@b.pl\x01auth=Bearer evil", 'tok');
    }

    public function testAuthenticateWithInitialResponseOnTheCommandLine()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 SASL-IR AUTH=XOAUTH2] ready\nA0001 OK [CAPABILITY IMAP4rev1 MOVE UIDPLUS] AUTHENTICATE completed.\n");
        $client->authenticateXoauth2('jan@firma.pl', 'ya29.token');

        $this->assertSame(['A0001 AUTHENTICATE XOAUTH2 ' . ImapClient::xoauth2('jan@firma.pl', 'ya29.token')], $this->sent());
        $this->assertTrue($client->hasCapability('MOVE'));
        $this->assertFalse($client->hasCapability('AUTH=XOAUTH2'), 'capabilities refreshed after login');
    }

    public function testAuthenticateWithoutSaslIrWaitsForTheContinuation()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2] ready\n+ \nA0001 OK done\nA0002 OK caps\n");
        $client->authenticateXoauth2('jan@firma.pl', 'tok');
        $sent = $this->sent();
        $this->assertSame('A0001 AUTHENTICATE XOAUTH2', $sent[0]);
        $this->assertSame(ImapClient::xoauth2('jan@firma.pl', 'tok'), $sent[1]);
        $this->assertSame('A0002 CAPABILITY', $sent[2]);
    }

    /** Google: the error is a base64 JSON challenge, answered with an empty line, then NO. */
    public function testRejectedTokenReportsTheServerChallenge()
    {
        $challenge = base64_encode('{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}');
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 SASL-IR AUTH=XOAUTH2] ready\n+ $challenge\nA0001 NO SASL authentication failed\n");
        try {
            $client->authenticateXoauth2('jan@gmail.com', 'expired');
            $this->fail('expected an exception');
        } catch (ImapException $e) {
            $this->assertStringContainsString('(XOAUTH2) odrzucone', $e->getMessage());
            $this->assertStringContainsString('status=401', $e->getMessage());
            $this->assertStringNotContainsString('expired', $e->getMessage(), 'the token never ends up in a message');
        }
        $sent = $this->sent();
        $this->assertCount(1, $sent, 'the challenge was answered with an empty line');
    }

    public function testServerWithoutXoauth2IsRefused()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\n");
        $this->expectException(ImapException::class);
        $this->expectExceptionMessage('AUTH=XOAUTH2');
        $client->authenticateXoauth2('a@b.pl', 'tok');
    }

    public function testFetchParsesLiteralsAndFlags()
    {
        $header = "From: Jan <jan@firma.pl>\r\nSubject: (test) {5}\r\n\r\n";
        $client = $this->client("* OK [CAPABILITY IMAP4rev1] ready\nA0001 OK [READ-WRITE] selected\n"
            . "* 3 FETCH (UID 42 FLAGS (\\Seen \\Flagged) INTERNALDATE \"28-Oct-2026 10:00:00 +0100\" RFC822.SIZE 1234 BODY[HEADER] {" . strlen($header) . "}\n"
            . str_replace("\r\n", "\n", $header) . ")\n"
            . "* 4 FETCH (FLAGS (\\Seen))\n"
            . "A0002 OK fetched\n");
        $client->select('INBOX');
        $data = $client->uidFetch([42], 'UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER]');

        $this->assertSame([42], array_keys($data), 'unsolicited FETCH without UID ignored');
        $this->assertSame($header, $data[42]['BODY[HEADER]']);
        $this->assertSame(['\\Seen', '\\Flagged'], $data[42]['FLAGS']);
        $this->assertSame('28-Oct-2026 10:00:00 +0100', $data[42]['INTERNALDATE']);
        $this->assertSame('1234', $data[42]['RFC822.SIZE']);
        $this->assertSame(['A0001 SELECT "INBOX"', 'A0002 UID FETCH 42 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER])'], $this->sent());
    }

    public function testPartialBodyFetchKeyIsNormalised()
    {
        $client = $this->client("* OK ready\nA0001 OK caps\n* 1 FETCH (UID 7 BODY[]<0> {3}\nabc)\nA0002 OK\n");
        $client->refreshCapabilities();
        $this->assertSame('abc', $client->uidFetch([7], 'UID BODY.PEEK[]<0.100>')[7]['BODY[]']);
    }

    public function testListStatusAndSearch()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1] ready\n"
            . "* LIST (\\HasNoChildren) \"/\" \"INBOX\"\n* LIST (\\HasNoChildren \\Junk) \"/\" \"[Gmail]/Spam\"\n* LIST (\\Noselect) NIL {4}\nSPAM\nA0001 OK\n"
            . "* STATUS \"INBOX\" (MESSAGES 3 UIDNEXT 11 UIDVALIDITY 1700000000)\nA0002 OK\n"
            . "* SEARCH 10 2 5\nA0003 OK\n");
        $boxes = $client->listMailboxes();
        $this->assertSame(['INBOX', '[Gmail]/Spam', 'SPAM'], array_column($boxes, 'name'));
        $this->assertSame('', $boxes[2]['delimiter']);
        $this->assertSame(['messages' => 3, 'uidnext' => 11, 'uidvalidity' => 1700000000], $client->status('INBOX', ['MESSAGES', 'UIDNEXT', 'UIDVALIDITY']));
        $this->assertSame([2, 5, 10], $client->uidSearch('SINCE "1-Oct-2026"'));
        $this->assertSame('A0003 UID SEARCH SINCE "1-Oct-2026"', $this->sent()[2]);
    }

    public function testNoAnswerBecomesAnException()
    {
        $client = $this->client("* OK ready\nA0001 NO [TRYCREATE] Mailbox doesn't exist: SPAM\n");
        $this->expectException(ImapException::class);
        $this->expectExceptionMessage('IMAP UID COPY: NO [TRYCREATE]');
        $client->uidCopy([1], 'SPAM');
    }

    /** Without MOVE: COPY + \Deleted, and expunge() removes only those UIDs (UIDPLUS). */
    public function testMoveFallbackAndTargetedExpunge()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 UIDPLUS] ready\nA0001 OK selected\nA0002 OK copied\nA0003 OK stored\nA0004 OK expunged\n");
        $connection = new SocketConnection($client);
        $connection->moveUids('INBOX', [5, 3], 'SPAM');
        $connection->expunge();
        $this->assertSame([
            'A0001 SELECT "INBOX"',
            'A0002 UID COPY 3,5 "SPAM"',
            'A0003 UID STORE 3,5 +FLAGS.SILENT (\\Deleted)',
            'A0004 UID EXPUNGE 3,5',
        ], $this->sent());
    }

    public function testMoveUsesUidMoveWhenAvailable()
    {
        $client = $this->client("* OK [CAPABILITY IMAP4rev1 MOVE] ready\nA0001 OK selected\nA0002 OK moved\n");
        $connection = new SocketConnection($client);
        $connection->moveUids('INBOX', [9], 'QUARANTINE');
        $connection->expunge(); // nothing flagged: no command
        $this->assertSame(['A0001 SELECT "INBOX"', 'A0002 UID MOVE 9 "QUARANTINE"'], $this->sent());
    }

    public function testByeAbortsTheCommand()
    {
        $client = $this->client("* OK ready\n* BYE server shutting down\n");
        $this->expectException(ImapException::class);
        $this->expectExceptionMessage('zakończył połączenie');
        try {
            $client->command('NOOP');
        } finally {
            $this->assertFalse($client->isConnected());
        }
    }

    public function testClosedConnectionIsReported()
    {
        $client = $this->client("* OK ready\n");
        fclose($this->server);
        $this->expectException(ImapException::class);
        $client->command('NOOP');
    }

    public function testQuotingAndEncoding()
    {
        $this->assertSame('"a\\"b\\\\c"', ImapClient::quote('a"b\\c'));
        $this->assertSame('"Wa&AXw-ne"', ImapClient::quoteMailbox('Ważne'));
        $this->assertSame('Ważne', ImapClient::decodeMailbox('Wa&AXw-ne'));
        $this->assertSame('1,3,7', ImapClient::uidSet([7, 3, 1, 3]));
        $this->assertSame('120:*', ImapClient::uidSet('120:*'));
        $this->expectException(\InvalidArgumentException::class);
        ImapClient::quote("x\r\nA1 LOGOUT");
    }

    public function testInvalidUidSetIsRejected()
    {
        $this->expectException(\InvalidArgumentException::class);
        ImapClient::uidSet('1 BODY[]');
    }

    public function testSearchCriteriaMustBeAscii()
    {
        $client = $this->client("* OK ready\n");
        $this->expectException(ImapException::class);
        $client->uidSearch("FROM \"x\"\r\nA9 DELETE INBOX");
    }

    public function testTokenizeNestedListsAndNil()
    {
        $this->assertSame([['\\HasChildren'], null, 'a b', ['X', ['Y', 'Z']], 'BODY[HEADER.FIELDS (FROM)]'],
            ImapClient::tokenize('(\\HasChildren) NIL "a b" (X (Y Z)) BODY[HEADER.FIELDS (FROM)]'));
    }
}
