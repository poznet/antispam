<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Services\MessageService;
use Ddeboer\Imap\MessageInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Filesystem\Filesystem;

class MessageServiceTest extends TestCase
{
    private $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/antispam-markers-' . bin2hex(random_bytes(4));
    }

    protected function tearDown(): void
    {
        (new Filesystem())->remove($this->dir);
    }

    private function msg($id, $uid = 1, $raw = "Received: from x\r\nFrom: a@b.c\r\n")
    {
        $m = $this->createMock(MessageInterface::class);
        $m->method('getId')->willReturn($id);
        $m->method('getNumber')->willReturn($uid);
        $m->method('getRawHeaders')->willReturn($raw);
        return $m;
    }

    public function testMessageWithoutIdIsNotCheckedUntilMarked()
    {
        $ms = new MessageService($this->dir);
        mkdir($this->dir, 0777, true); // the marker dir exists - the old bug made every id-less message "checked"

        $msg = $this->msg(null);
        $this->assertFalse($ms->isChecked($msg, 'box@firma.pl'));

        $ms->setAsChecked($msg, 'box@firma.pl');
        $this->assertTrue($ms->isChecked($msg, 'box@firma.pl'));

        // A different id-less message (other headers) is still unchecked.
        $this->assertFalse($ms->isChecked($this->msg(null, 2, "Received: from y\r\n"), 'box@firma.pl'));
    }

    public function testMarkersAreScopedPerMailbox()
    {
        $ms = new MessageService($this->dir);
        $msg = $this->msg('<abc@sender.pl>');

        $ms->setAsChecked($msg, 'one@firma.pl');
        $this->assertTrue($ms->isChecked($msg, 'ONE@firma.pl'));
        $this->assertFalse($ms->isChecked($msg, 'two@firma.pl'), 'the same message delivered to a 2nd mailbox must be scanned there too');
    }

    public function testUnscopedMarkerAppliesToEveryMailbox()
    {
        $ms = new MessageService($this->dir);
        $msg = $this->msg('<released@sender.pl>');

        $ms->setAsChecked($msg); // e.g. released from quarantine by a caller that does not pass the mailbox
        $this->assertTrue($ms->isChecked($msg, 'one@firma.pl'));
        $this->assertTrue($ms->isChecked($msg));

        $ms->unCheck($msg, 'one@firma.pl');
        $this->assertFalse($ms->isChecked($msg, 'one@firma.pl'));
    }

    public function testLegacyMarkersAreStillHonoured()
    {
        mkdir($this->dir, 0777, true);
        file_put_contents($this->dir . '/old_id@sender.pl', '5'); // pre-v2 name: Message-ID with "/" replaced
        $ms = new MessageService($this->dir);

        $this->assertTrue($ms->isChecked($this->msg('old/id@sender.pl'), 'box@firma.pl'));
        $this->assertTrue($ms->hasAnyMarkers());
    }

    public function testVeryLongMessageIdWorks()
    {
        $ms = new MessageService($this->dir);
        $msg = $this->msg('<' . str_repeat('x', 400) . '@sender.pl>');

        $ms->setAsChecked($msg, 'box@firma.pl');
        $this->assertTrue($ms->isChecked($msg, 'box@firma.pl'));
    }

    public function testPurgeRemovesOnlyOldMarkers()
    {
        $ms = new MessageService($this->dir);
        $old = $this->msg('<old@x>');
        $new = $this->msg('<new@x>');
        $ms->setAsChecked($old, 'box@firma.pl');
        $ms->setAsChecked($new, 'box@firma.pl');
        file_put_contents($this->dir . '/legacy@x', '1');

        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS)) as $file) {
            touch($file->getPathname(), time() - 100 * 86400);
        }
        // Re-mark the "new" one, so only it is fresh.
        $ms->unCheck($new, 'box@firma.pl');
        $ms->setAsChecked($new, 'box@firma.pl');

        $this->assertSame(2, $ms->purgeOlderThan(90));
        $this->assertFalse($ms->isChecked($old, 'box@firma.pl'));
        $this->assertTrue($ms->isChecked($new, 'box@firma.pl'));
        $this->assertFileDoesNotExist($this->dir . '/legacy@x');
    }

    public function testPurgeIfDueRunsOncePerInterval()
    {
        $ms = new MessageService($this->dir);
        $ms->setAsChecked($this->msg('<a@x>'), 'box@firma.pl');

        $this->assertSame(0, $ms->purgeIfDue());
        $this->assertNull($ms->purgeIfDue());
        $this->assertTrue($ms->hasAnyMarkers(), 'the purge stamp alone does not count as a marker');
    }

    public function testUnCheckAllWithoutDatabase()
    {
        $ms = new MessageService($this->dir);
        $msg = $this->msg('<a@x>');
        $ms->setAsChecked($msg, 'box@firma.pl');

        $ms->unCheckAll();
        $this->assertFalse($ms->isChecked($msg, 'box@firma.pl'));
        $this->assertFalse($ms->hasAnyMarkers());
    }
}
