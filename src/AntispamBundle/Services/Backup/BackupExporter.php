<?php

namespace AntispamBundle\Services\Backup;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\Config;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\ListSetting;
use AntispamBundle\Entity\User;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\CryptoService;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Builds the configuration backup (see BackupFormat): settings, list rules,
 * DNSBL providers, accounts and users. Phishing reports, quarantine, score log,
 * cron log and other runtime data are never included.
 *
 * Secrets (IMAP / legacy mailbox passwords, API keys, feed keys, password
 * hashes, plugin password hashes, SSH key paths) are only exported with
 * $includeSecrets, and then every one of them is encrypted with the instance
 * key (CryptoService, derived from APP_SECRET) - an import elsewhere needs the
 * same APP_SECRET to use them.
 */
class BackupExporter
{
    /** list type => [entity, value field, has score] */
    public const RULE_LISTS = [
        'blacklist' => [Blacklist::class, 'host', true],
        'whitelist' => [Whitelist::class, 'host', false],
        'email_blacklist' => [EmailBlacklist::class, 'blacklistemail', true],
        'email_whitelist' => [EmailWhitelist::class, 'whitelistemail', false],
    ];

    /** @var string[] problems met while exporting (e.g. a secret that cannot be decrypted) */
    private array $warnings = [];

    public function __construct(
        private EntityManagerInterface $em,
        private CryptoService $crypto,
        private AppVersion $version,
    ) {
    }

    public function export(bool $includeSecrets = false): array
    {
        $this->warnings = [];

        return [
            'format' => BackupFormat::FORMAT,
            'schema_version' => BackupFormat::SCHEMA_VERSION,
            'app_version' => $this->version->get(),
            'exported_at' => (new \DateTimeImmutable())->format(DATE_ATOM),
            'include_secrets' => $includeSecrets,
            'secrets' => $includeSecrets ? [
                'cipher' => rtrim(CryptoService::PREFIX, ':'),
                'note' => 'Secrets are encrypted with a key derived from APP_SECRET of the exporting instance; the target needs the same APP_SECRET.',
                'key_check' => $this->crypto->encrypt(BackupFormat::KEY_CHECK_PLAINTEXT),
            ] : null,
            'settings' => $this->settings($includeSecrets),
            'rules' => $this->rules(),
            'dnsbl' => $this->dnsbl(),
            'accounts' => $this->accounts($includeSecrets),
            'users' => $this->users($includeSecrets),
        ];
    }

    /** @return string[] */
    public function getWarnings(): array
    {
        return $this->warnings;
    }

    private function settings(bool $includeSecrets): array
    {
        $config = [];
        $secrets = [];
        foreach ($this->em->getRepository(Config::class)->findBy([], ['name' => 'ASC']) as $row) {
            $name = (string)$row->getName();
            if ($name === '' || BackupSecrets::isState($name) || isset($config[$name])) {
                continue;
            }
            $value = $row->getValue();
            if (BackupSecrets::isSecret($name)) {
                if ($includeSecrets && (string)$value !== '') {
                    $sealed = $this->seal((string)$value, 'setting ' . $name);
                    if ($sealed !== null) {
                        $secrets[$name] = $sealed;
                    }
                }
                continue;
            }
            if (!is_scalar($value) && $value !== null) {
                $this->warnings[] = 'Setting ' . $name . ' has a non-scalar value - skipped.';
                continue;
            }
            $config[$name] = $value;
        }

        $lists = [];
        foreach ($this->em->getRepository(ListSetting::class)->findBy([], ['name' => 'ASC']) as $row) {
            $lists[(string)$row->getName()] = $row->getValue();
        }

        $out = ['config' => (object)$config, 'lists' => (object)$lists];
        if ($includeSecrets) {
            $out['secrets'] = (object)$secrets;
        }

        return $out;
    }

    private function rules(): array
    {
        $out = [];
        foreach (self::RULE_LISTS as $type => [$entity, $field, $withScore]) {
            $getter = 'get' . ucfirst($field);
            $out[$type] = [];
            foreach ($this->em->getRepository($entity)->findBy([], ['id' => 'ASC']) as $rule) {
                $item = [
                    'owner' => (string)$rule->getEmail(),
                    'value' => (string)$rule->$getter(),
                    'pattern_type' => $rule->getPatternType() ?: 'exact',
                ];
                if ($withScore) {
                    $item['score'] = (int)$rule->getScore();
                }
                $item['hits'] = (int)$rule->getCounter();
                $out[$type][] = $item;
            }
        }

        return $out;
    }

    private function dnsbl(): array
    {
        $out = [];
        foreach ($this->em->getRepository(DnsblProvider::class)->findBy([], ['id' => 'ASC']) as $p) {
            $out[] = [
                'name' => (string)$p->getName(),
                'zone' => (string)$p->getZone(),
                'score' => (int)$p->getScore(),
                'enabled' => (bool)$p->isEnabled(),
                'cache_ttl' => (int)$p->getCacheTtl(),
                'hits' => (int)$p->getHits(),
            ];
        }

        return $out;
    }

    private function accounts(bool $includeSecrets): array
    {
        $out = [];
        foreach ($this->em->getRepository(Account::class)->findBy([], ['id' => 'ASC']) as $a) {
            $item = [
                'email' => (string)$a->getEmail(),
                'name' => (string)$a->getName(),
                'connection_type' => (string)$a->getConnectionType(),
                'delete_spam' => (bool)$a->getDeleteSpam(),
                'imap_host' => $a->getImapHost(),
                'imap_port' => $a->getImapPort() === null ? null : (int)$a->getImapPort(),
                'imap_login' => $a->getImapLogin(),
                'imap_flags' => $a->getImapFlags(),
                'ssh_host' => $a->getSshHost(),
                'ssh_port' => $a->getSshPort() === null ? null : (int)$a->getSshPort(),
                'ssh_user' => $a->getSshUser(),
                'maildir_path' => $a->getMaildirPath(),
                'agent_path' => $a->getAgentPath(),
                // Public fingerprint, not a secret: keeps the TOFU pin across servers.
                'ssh_host_key' => $a->getSshHostKey(),
                'agent_deployed' => (bool)$a->getAgentDeployed(),
                // Per-mailbox settings (null = inherit the global setting).
                'spam_threshold' => $a->getSpamThreshold(),
                'quarantine_threshold' => $a->getQuarantineThreshold(),
                'scoring_enabled' => $a->getScoringEnabled(),
                'digest_enabled' => $a->getDigestEnabled(),
                'digest_recipient' => $a->getDigestRecipient(),
                'digest_hour' => $a->getDigestHour(),
            ];
            if ($includeSecrets) {
                // A path, not key material - the key file itself is copied with var/data (docs/backup.md).
                $item['ssh_key_path'] = $a->getSshKeyPath();
                $label = 'account ' . $a->getEmail();
                $item['imap_password'] = (string)$a->getImapPassword() !== '' ? $this->seal((string)$a->getImapPassword(), $label . ' (IMAP password)') : null;
                $item['plugin_password_hash'] = (string)$a->getPluginPasswordHash() !== '' ? $this->seal((string)$a->getPluginPasswordHash(), $label . ' (plugin password)') : null;
            }
            $out[] = $item;
        }

        return $out;
    }

    private function users(bool $includeSecrets): array
    {
        $out = [];
        foreach ($this->em->getRepository(User::class)->findBy([], ['username' => 'ASC']) as $u) {
            $emails = [];
            foreach ($u->getAccounts() as $account) {
                $emails[] = (string)$account->getEmail();
            }
            sort($emails);
            $item = [
                'username' => (string)$u->getUsername(),
                'role' => (string)$u->getRole(),
                'accounts' => $emails,
            ];
            if ($includeSecrets) {
                $item['password_hash'] = (string)$u->getPassword() !== '' ? $this->seal((string)$u->getPassword(), 'user ' . $u->getUsername()) : null;
            }
            $out[] = $item;
        }

        return $out;
    }

    /** Stored value (plain or already encrypted) -> encrypted with the instance key; null when unreadable. */
    private function seal(string $stored, string $label): ?string
    {
        try {
            $plain = (string)$this->crypto->decrypt($stored);
        } catch (\RuntimeException $e) {
            $this->warnings[] = 'Cannot decrypt the stored secret of ' . $label . ' (was APP_SECRET changed?) - left out of the export.';
            return null;
        }

        return $plain === '' ? null : $this->crypto->encrypt($plain);
    }
}
