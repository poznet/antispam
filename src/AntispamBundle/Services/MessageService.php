<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Ddeboer\Imap\Message\BasicMessageInterface;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Remembers which IMAP messages were already checked: one marker file per
 * (mailbox, message) in var/data/checked/v2/<2 hex>/<sha1>.
 *
 * The key is sha1(account e-mail + Message-ID), so the same message delivered
 * to two monitored mailboxes is filtered in both, a marker survives the move
 * between INBOX and QUARANTINE (release) and any Message-ID length is fine.
 * Mail without a Message-ID is keyed by a hash of its raw header block (it
 * holds the per-delivery Received lines, so it is unique and also survives a
 * move). An empty account means "any mailbox" (markers written by callers
 * that do not know the mailbox).
 *
 * Markers are only the second line of defence: the scan reads INBOX
 * incrementally from a per-mailbox UID cursor (ImapScanService), so a marker
 * is needed only for mail that re-enters INBOX above the cursor (released
 * from quarantine, a retried failure). That is why they can be purged after
 * MARKER_RETENTION_DAYS. Pre-v2 markers (file named after the raw
 * Message-ID, global for all mailboxes) are still honoured until purged.
 */
class MessageService
{
    const MARKER_RETENTION_DAYS = 90;
    /** Run the purge at most this often (seconds). */
    const PURGE_INTERVAL = 86400;

    private $dir;
    private $fs;

    public function __construct(
        #[Autowire('%kernel.project_dir%/var/data/checked')] string $dir,
        private ?EntityManagerInterface $em = null,
        private ?ConfigService $config = null,
    ) {
        $this->dir = rtrim($dir, '/');
        $this->fs = new Filesystem();
    }

    /**
     * Marks the message as checked in the given mailbox (creates its marker).
     *
     * @param string|null $account e-mail of the scanned mailbox; null = any mailbox
     */
    public function setAsChecked(BasicMessageInterface $msg, $account = null)
    {
        $name = $this->path($this->messageKey($msg), $account);
        if (!$this->fs->exists($name)) {
            $this->fs->dumpFile($name, (string)$msg->getNumber());
        }
    }

    /**
     * @param string|null $account e-mail of the scanned mailbox; null = only "any mailbox" markers
     */
    public function isChecked(BasicMessageInterface $msg, $account = null)
    {
        $key = $this->messageKey($msg);
        if ($account !== null && $account !== '' && is_file($this->path($key, $account))) {
            return true;
        }
        if (is_file($this->path($key, null))) {
            return true;
        }
        $legacy = $this->legacyPath($msg);
        return $legacy !== null && @is_file($legacy);
    }

    /**
     * Forgets the message (removes its markers, scoped and global).
     */
    public function unCheck(BasicMessageInterface $msg, $account = null)
    {
        $key = $this->messageKey($msg);
        $paths = [$this->path($key, null)];
        if ($account !== null && $account !== '') {
            $paths[] = $this->path($key, $account);
        }
        if (($legacy = $this->legacyPath($msg)) !== null) {
            $paths[] = $legacy;
        }
        $this->fs->remove($paths);
    }

    /**
     * Forgets all messages (removes every marker) and asks every IMAP mailbox
     * for a full INBOX pass on its next scan - that is what the "reset checked
     * flags" button promises. Without the cursor reset the incremental scan
     * would never look at mail below the cursor again.
     */
    public function unCheckAll()
    {
        $this->fs->remove($this->dir);
        if ($this->em) {
            $this->em->createQuery('UPDATE ' . Account::class . ' a SET a.imapUidValidity = 0, a.imapLastUid = 0 WHERE a.connectionType = :imap')
                ->setParameter('imap', Account::CONNECTION_IMAP)
                ->execute();
        }
        if ($this->config) {
            $this->config->set(ImapScanService::LEGACY_CURSOR_KEY, ImapScanService::encodeCursor(ImapScanService::fullRescanCursor()));
        }
    }

    /**
     * True when any marker exists - i.e. this install has scanned mail
     * before (used to tell an upgrade from a fresh install).
     */
    public function hasAnyMarkers()
    {
        if (!is_dir($this->dir)) {
            return false;
        }
        foreach (new \FilesystemIterator($this->dir) as $entry) {
            if ($entry->getFilename()[0] !== '.') {
                return true;
            }
        }
        return false;
    }

    /**
     * Removes markers (v2 and pre-v2) not touched for $days days.
     *
     * @return int number of markers removed
     */
    public function purgeOlderThan($days = self::MARKER_RETENTION_DAYS)
    {
        if (!is_dir($this->dir)) {
            return 0;
        }
        $limit = time() - (int)$days * 86400;
        $removed = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            if ($file->isFile() && $file->getFilename()[0] !== '.' && $file->getMTime() < $limit) {
                if (@unlink($file->getPathname())) {
                    $removed++;
                }
            }
        }
        return $removed;
    }

    /**
     * purgeOlderThan() at most once per PURGE_INTERVAL; called after every
     * IMAP scan so the marker directory cannot grow without bound.
     *
     * @return int|null number removed, null when the purge was not due
     */
    public function purgeIfDue()
    {
        $stamp = $this->dir . '/.last-purge';
        if (is_file($stamp) && filemtime($stamp) > time() - self::PURGE_INTERVAL) {
            return null;
        }
        try {
            $this->fs->dumpFile($stamp, (string)time());
        } catch (\Throwable $e) {
            return null;
        }
        return $this->purgeOlderThan();
    }

    /** Message-ID, or a hash of the raw header block when there is none. */
    private function messageKey(BasicMessageInterface $msg)
    {
        $id = null;
        try {
            $id = $msg->getId();
        } catch (\Throwable $e) {
            // unreadable headers: fall back to the raw block below
        }
        $id = trim((string)$id);
        if ($id !== '') {
            return 'id:' . $id;
        }
        return 'raw:' . sha1($msg->getRawHeaders());
    }

    private function path($key, $account)
    {
        $hash = sha1(strtolower(trim((string)$account)) . "\0" . $key);
        return $this->dir . '/v2/' . substr($hash, 0, 2) . '/' . $hash;
    }

    /** Pre-v2 marker: the raw Message-ID as a file name (null without an id). */
    private function legacyPath(BasicMessageInterface $msg)
    {
        try {
            $id = (string)$msg->getId();
        } catch (\Throwable $e) {
            return null;
        }
        $name = str_replace(['/', '\\'], '_', $id);
        // No id = the directory itself (the old bug); too long = never written.
        if ($name === '' || $name === '.' || $name === '..' || $name === 'v2' || strlen($name) > 255) {
            return null;
        }
        return $this->dir . '/' . $name;
    }
}
