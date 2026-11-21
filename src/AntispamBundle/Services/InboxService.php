<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\ConnectionInterface;

class InboxService
{
    private $spamboxname = 'SPAM';
    private $quarantineboxname = 'QUARANTINE';
    /** @var \WeakMap<ConnectionInterface, array<string, string>>|null folder names found per connection */
    private ?\WeakMap $resolved = null;

    public const KIND_SPAM = 'spam';
    public const KIND_QUARANTINE = 'quarantine';

    /**
     * The SPAM folder of a mailbox (created when it has none).
     */
    public function getSpamFolder(ConnectionInterface $connection)
    {
        return $this->getOrCreateFolder(self::KIND_SPAM, $connection);
    }

    /**
     * Name of the SPAM folder. With a connection: the folder that mailbox
     * already has ("SPAM", else "Spam", "INBOX.Spam", "Junk", "[Gmail]/Spam"…
     * - servers such as poczta.interia.pl refuse CREATE "SPAM" next to their
     * own "Spam"), else the default "SPAM".
     */
    public function getSpamFolderName(?ConnectionInterface $connection = null)
    {
        return $connection ? $this->resolve(self::KIND_SPAM, $connection) : $this->spamboxname;
    }

    /**
     * Returns (creating if needed) the quarantine folder used for messages
     * whose score is suspicious but below the spam threshold.
     */
    public function getQuarantineFolder(ConnectionInterface $connection)
    {
        return $this->getOrCreateFolder(self::KIND_QUARANTINE, $connection);
    }

    public function getQuarantineFolderName(?ConnectionInterface $connection = null)
    {
        return $connection ? $this->resolve(self::KIND_QUARANTINE, $connection) : $this->quarantineboxname;
    }

    /**
     * Existing folder of the kind: the default name exactly, else the same
     * name in another case / under INBOX, else (SPAM only) the server's
     * junk folder. The default name when there is none.
     */
    public function resolve(string $kind, ConnectionInterface $connection): string
    {
        $this->resolved ??= new \WeakMap();
        if (isset($this->resolved[$connection][$kind])) {
            return $this->resolved[$connection][$kind];
        }
        $default = $kind === self::KIND_SPAM ? $this->spamboxname : $this->quarantineboxname;
        $found = $connection->hasMailbox($default) ? $default : self::findExisting($kind, array_map('strval', array_keys($connection->getMailboxes())));
        $map = $this->resolved[$connection] ?? [];
        $map[$kind] = $found ?? $default;
        $this->resolved[$connection] = $map;
        return $map[$kind];
    }

    /**
     * @param string[] $names folder names of the mailbox
     */
    public static function findExisting(string $kind, array $names): ?string
    {
        $groups = $kind === self::KIND_SPAM
            ? [['spam'], ['junk', 'junk e-mail', 'junk email', 'junk mail', 'bulk mail', 'wiadomości-śmieci', 'niechciane', 'śmieci']]
            : [['quarantine', 'kwarantanna']];
        foreach ($groups as $wanted) {
            $best = null;
            foreach ($names as $name) {
                $last = mb_strtolower((string)preg_replace('~^.*[./]~', '', $name));
                if (!in_array($last, $wanted, true)) {
                    continue;
                }
                // Top level first, then INBOX.<name>, then anything deeper.
                $rank = !preg_match('~[./]~', $name) ? 0 : (preg_match('~^inbox[./][^./]+$~i', $name) ? 1 : 2);
                if ($best === null || $rank < $best[0]) {
                    $best = [$rank, $name];
                }
            }
            if ($best !== null) {
                return $best[1];
            }
        }
        return null;
    }

    private function getOrCreateFolder(string $kind, ConnectionInterface $connection)
    {
        $name = $this->resolve($kind, $connection);
        if ($connection->hasMailbox($name)) {
            return $connection->getMailbox($name);
        }
        try {
            $folder = $connection->createMailbox($name);
        } catch (\Throwable $e) {
            // Some servers only allow folders under INBOX (INBOX.SPAM).
            $delimiter = $connection->hasMailbox('INBOX') ? (string)$connection->getMailbox('INBOX')->getDelimiter() : '';
            if ($delimiter === '' || $delimiter === 'NIL') {
                throw $this->createError($name, $e);
            }
            try {
                $folder = $connection->createMailbox('INBOX' . $delimiter . $name);
            } catch (\Throwable) {
                throw $this->createError($name, $e);
            }
        }
        unset($this->resolved[$connection]);
        return $folder;
    }

    private function createError(string $name, \Throwable $e): \RuntimeException
    {
        return new \RuntimeException(sprintf('Serwer IMAP nie pozwala utworzyć folderu „%s” (ani „INBOX/%s”) - utwórz go ręcznie w poczcie albo folder spamu skrzynki. Błąd serwera: %s', $name, $name, $e->getMessage()), 0, $e);
    }
}
