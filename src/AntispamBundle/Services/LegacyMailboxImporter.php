<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Moves the old single mailbox of the "Konfiguracja (stara)" settings page
 * (config keys email / login / password / imap / imap_port / imap_flags) to a
 * regular IMAP account in *Konta*, so the panel has one kind of mailbox only.
 * Run by `antispam:db:upgrade` at every boot; idempotent.
 *
 * Kept on the way: the address (rules, score log, digest settings and stats
 * are keyed by it, so they stay with the mailbox), the encrypted password,
 * the TLS flags, the "delete spam" switch, the digest recipient and the scan cursor (no rescan of
 * the whole INBOX). Checked-message markers of the old mailbox are global
 * ("any mailbox") ones, MessageService::isChecked() still sees them.
 *
 * When an account with the same address already exists, the legacy settings
 * are only removed. The settings are removed after the account is stored.
 */
class LegacyMailboxImporter
{
    /** Config keys of the old mailbox (cleared after the import). */
    public const KEYS = ['email', 'login', 'password', 'imap', 'imap_port', 'imap_flags', 'imap.legacy_cursor', 'digest.imap_recipient'];

    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private CryptoService $crypto,
    ) {
    }

    /** Is an old mailbox still configured? */
    public function pending(): bool
    {
        return trim((string)$this->config->get('imap')) !== '' && trim((string)$this->config->get('login')) !== '';
    }

    /**
     * @return string|null what was done (for the upgrade log), null = nothing to import
     */
    public function import(): ?string
    {
        if (!$this->pending()) {
            return null;
        }
        $login = trim((string)$this->config->get('login'));
        $email = strtolower(trim((string)$this->config->get('email')));
        if ($email === '' || !str_contains($email, '@')) {
            $email = str_contains($login, '@') ? strtolower($login) : $email;
        }
        if ($email === '') {
            return 'Stara skrzynka bez adresu e-mail - nie przeniesiono, uzupełnij ją ręcznie w Konta.';
        }

        $existing = $this->em->createQueryBuilder()->select('a')->from(Account::class, 'a')
            ->where('LOWER(a.email) = :email')->setParameter('email', $email)
            ->setMaxResults(1)->getQuery()->getOneOrNullResult();
        if ($existing instanceof Account) {
            $this->clear();
            return sprintf('Stara skrzynka %s jest już w Konta (#%d) - usunięto tylko jej stare ustawienia.', $email, $existing->getId());
        }

        $plain = $this->crypto->decrypt((string)$this->config->get('password'));
        $account = (new Account())
            ->setName($email)
            ->setEmail($email)
            ->setConnectionType(Account::CONNECTION_IMAP)
            ->setImapHost(trim((string)$this->config->get('imap')))
            ->setImapPort((int)($this->config->get('imap_port') ?: 993))
            ->setImapLogin($login)
            ->setImapPassword($plain !== '' ? $this->crypto->encrypt($plain) : null)
            ->setImapFlags(ImapFlags::sanitize((string)($this->config->get('imap_flags') ?: ImapFlags::DEFAULT_FLAGS)))
            ->setDeleteSpam((bool)$this->config->get('delete'));
        $recipient = strtolower(trim((string)$this->config->get('digest.imap_recipient')));
        if ($recipient !== '' && $recipient !== $email) {
            $account->setDigestRecipient($recipient);
        }
        $cursor = ImapScanService::decodeCursor($this->config->get('imap.legacy_cursor'));
        if ($cursor !== null) {
            $account->setImapCursor($cursor);
            $account->setLastScanAt((new \DateTime())->setTimestamp($cursor['scanned_at'] ?? time()));
        }
        $this->em->persist($account);
        $this->em->flush();
        $this->clear();

        return sprintf('Stara skrzynka %s przeniesiona do Konta (#%d).', $email, $account->getId());
    }

    private function clear(): void
    {
        foreach (self::KEYS as $key) {
            if ($this->config->get($key) !== null) {
                $this->config->set($key, '');
            }
        }
    }
}
