<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Event\MessageEvent;
use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Server;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Runs the INBOX of an IMAP mailbox through the `antispam.check.message`
 * pipeline: spam goes to SPAM (or is deleted), suspicious mail to QUARANTINE.
 * Used for both IMAP accounts (Konta) and the legacy mailbox from the
 * "E-mail" settings, by the panel and by `antispam:agent:scan-all`.
 */
class ImapScanService
{
    public function __construct(
        private EventDispatcherInterface $dispatcher,
        private ConnectionService $legacyConnection,
        private ConfigService $config,
        private CryptoService $crypto,
    ) {
    }

    /** Opens an IMAP connection for an IMAP account. */
    public function connect(Account $account): ConnectionInterface
    {
        $server = new Server($account->getImapHost(), $account->getImapPort(), $account->getImapFlags());
        return $server->authenticate($account->getImapLogin(), (string)$this->crypto->decrypt($account->getImapPassword()));
    }

    public function isLegacyConfigured(): bool
    {
        return $this->config->get('imap') && $this->config->get('login');
    }

    public function scanAccount(Account $account): array
    {
        $connection = $this->connect($account);
        try {
            return $this->scan($connection, $account->getEmail(), (bool)$account->getDeleteSpam(), $account->getLastScanAt() === null);
        } finally {
            $connection->close();
        }
    }

    /** The mailbox from the "E-mail" settings page (`antispam:go`). */
    public function scanLegacy(): array
    {
        return $this->scan($this->legacyConnection->getConnection(), (string)$this->config->get('email'), null);
    }

    /**
     * @param bool|null $deleteSpam null = global "delete" setting
     * @param bool $initialScan first scan of a newly connected mailbox (kept out of stats)
     *
     * @return array counters + 'errors' (list of strings, at most 20)
     */
    public function scan(ConnectionInterface $connection, $email, ?bool $deleteSpam, bool $initialScan = false): array
    {
        $stats = ['total' => 0, 'checked' => 0, 'skipped' => 0, 'whitelisted' => 0, 'blacklisted' => 0,
                  'quarantined' => 0, 'moved_to_spam' => 0, 'errors' => []];

        foreach ($connection->getMailbox('INBOX')->getMessages() as $msg) {
            $stats['total']++;
            try {
                $event = new MessageEvent($msg, $email, $connection, $deleteSpam);
                $event->setInitialScan($initialScan);
                $this->dispatcher->dispatch($event, 'antispam.check.message');

                if ($event->isCheckedbefore()) {
                    $stats['skipped']++;
                    continue;
                }
                $stats['checked']++;
                if ($event->isWhitelist()) { $stats['whitelisted']++; }
                if ($event->isBlacklist()) { $stats['blacklisted']++; }
                if ($event->isDelete()) {
                    $event->isSpam() ? $stats['moved_to_spam']++ : $stats['quarantined']++;
                }
            } catch (\Throwable $e) {
                if (count($stats['errors']) < 20) {
                    $stats['errors'][] = 'UID ' . $msg->getNumber() . ': ' . $e->getMessage();
                }
            }
        }

        if ($stats['moved_to_spam'] + $stats['quarantined'] > 0) {
            $connection->expunge();
        }

        return $stats;
    }
}
