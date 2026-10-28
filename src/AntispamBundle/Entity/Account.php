<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\AccountRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: AccountRepository::class)]
#[ORM\Table(name: 'antispam_account')]
class Account
{
    const CONNECTION_IMAP = 'imap';
    const CONNECTION_SSH = 'ssh';

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'name', type: 'string', length: 255)]
    private $name;

    #[ORM\Column(name: 'email', type: 'string', length: 255)]
    private $email;

    #[ORM\Column(name: 'connection_type', type: 'string', length: 10)]
    private $connectionType = self::CONNECTION_IMAP;

    // IMAP fields

    #[ORM\Column(name: 'imap_host', type: 'string', length: 255, nullable: true)]
    private $imapHost;

    #[ORM\Column(name: 'imap_port', type: 'integer', nullable: true)]
    private $imapPort = 993;

    #[ORM\Column(name: 'imap_login', type: 'string', length: 255, nullable: true)]
    private $imapLogin;

    #[ORM\Column(name: 'imap_password', type: 'string', length: 255, nullable: true)]
    private $imapPassword;

    #[ORM\Column(name: 'imap_flags', type: 'string', length: 255, nullable: true)]
    private $imapFlags = '/imap/ssl';

    // SSH fields

    #[ORM\Column(name: 'ssh_host', type: 'string', length: 255, nullable: true)]
    private $sshHost;

    #[ORM\Column(name: 'ssh_port', type: 'integer', nullable: true)]
    private $sshPort = 22;

    #[ORM\Column(name: 'ssh_user', type: 'string', length: 255, nullable: true)]
    private $sshUser;

    #[ORM\Column(name: 'ssh_key_path', type: 'string', length: 500, nullable: true)]
    private $sshKeyPath;

    #[ORM\Column(name: 'maildir_path', type: 'string', length: 500, nullable: true)]
    private $maildirPath = '~/Maildir';

    #[ORM\Column(name: 'agent_path', type: 'string', length: 500, nullable: true)]
    private $agentPath = '~/antispam-agent';

    /**
     * SHA256 fingerprint of the SSH server's host key, pinned on the first
     * successful connection (trust on first use). null = not pinned yet.
     */
    #[ORM\Column(name: 'ssh_host_key', type: 'string', length: 255, nullable: true)]
    private $sshHostKey;

    // Common fields

    #[ORM\Column(name: 'delete_spam', type: 'boolean')]
    private $deleteSpam = false;

    #[ORM\Column(name: 'agent_deployed', type: 'boolean')]
    private $agentDeployed = false;

    #[ORM\Column(name: 'last_scan_at', type: 'datetime', nullable: true)]
    private $lastScanAt;

    #[ORM\Column(name: 'last_scan_result', type: 'text', nullable: true)]
    private $lastScanResult;

    /**
     * bcrypt hash of the password used to log in from the Thunderbird plugin
     * (optional; IMAP accounts can also log in with their IMAP password).
     */
    #[ORM\Column(name: 'plugin_password_hash', type: 'string', length: 255, nullable: true)]
    private $pluginPasswordHash;

    /**
     * IMAP scan cursor: UIDVALIDITY of INBOX and the highest UID already run
     * through the pipeline, so a scan only fetches newer mail. Both null =
     * no cursor yet; 0/0 = full INBOX pass requested ("reset checked flags").
     */
    #[ORM\Column(name: 'imap_uid_validity', type: 'bigint', nullable: true)]
    private $imapUidValidity;

    #[ORM\Column(name: 'imap_last_uid', type: 'bigint', nullable: true)]
    private $imapLastUid;

    // Per-mailbox settings ("Ustawienia skrzynki"). null = inherit the global
    // value; MailboxSettingsResolver turns them into the effective settings.

    /** Spam threshold override (null = scoring.spam_threshold). */
    #[ORM\Column(name: 'spam_threshold', type: 'integer', nullable: true)]
    private $spamThreshold;

    /** Quarantine threshold override (null = scoring.quarantine_threshold). */
    #[ORM\Column(name: 'quarantine_threshold', type: 'integer', nullable: true)]
    private $quarantineThreshold;

    /** Scoring on/off override (null = scoring.enabled). */
    #[ORM\Column(name: 'scoring_enabled', type: 'boolean', nullable: true)]
    private $scoringEnabled;

    /** Quarantine digest for this mailbox on/off (null = digest.enabled). */
    #[ORM\Column(name: 'digest_enabled', type: 'boolean', nullable: true)]
    private $digestEnabled;

    /** Digest recipient instead of the mailbox address (e.g. a department head); null = the account e-mail. */
    #[ORM\Column(name: 'digest_recipient', type: 'string', length: 255, nullable: true)]
    private $digestRecipient;

    /** Hour (0-23, server time) to send this mailbox's digest; null = with the global antispam:digest:send run. */
    #[ORM\Column(name: 'digest_hour', type: 'smallint', nullable: true)]
    private $digestHour;

    public function getId() { return $this->id; }

    public function getName() { return $this->name; }
    public function setName($name) { $this->name = $name; return $this; }

    public function getEmail() { return $this->email; }
    public function setEmail($email) { $this->email = $email; return $this; }

    public function getConnectionType() { return $this->connectionType; }
    public function setConnectionType($connectionType) { $this->connectionType = $connectionType; return $this; }

    public function isImap() { return $this->connectionType === self::CONNECTION_IMAP; }
    public function isSsh() { return $this->connectionType === self::CONNECTION_SSH; }

    public function getImapHost() { return $this->imapHost; }
    public function setImapHost($imapHost) { $this->forgetCursorIfChanged($this->imapHost, $imapHost); $this->imapHost = $imapHost; return $this; }

    public function getImapPort() { return $this->imapPort; }
    public function setImapPort($imapPort) { $this->forgetCursorIfChanged($this->imapPort, $imapPort); $this->imapPort = $imapPort; return $this; }

    public function getImapLogin() { return $this->imapLogin; }
    public function setImapLogin($imapLogin) { $this->forgetCursorIfChanged($this->imapLogin, $imapLogin); $this->imapLogin = $imapLogin; return $this; }

    public function getImapPassword() { return $this->imapPassword; }
    public function setImapPassword($imapPassword) { $this->imapPassword = $imapPassword; return $this; }

    public function getImapFlags() { return $this->imapFlags; }
    public function setImapFlags($imapFlags) { $this->imapFlags = $imapFlags; return $this; }

    public function getSshHost() { return $this->sshHost; }
    public function setSshHost($sshHost) { $this->sshHost = $sshHost; return $this; }

    public function getSshPort() { return $this->sshPort; }
    public function setSshPort($sshPort) { $this->sshPort = $sshPort; return $this; }

    public function getSshUser() { return $this->sshUser; }
    public function setSshUser($sshUser) { $this->sshUser = $sshUser; return $this; }

    public function getSshKeyPath() { return $this->sshKeyPath; }
    public function setSshKeyPath($sshKeyPath) { $this->sshKeyPath = $sshKeyPath; return $this; }

    public function getMaildirPath() { return $this->maildirPath; }
    public function setMaildirPath($maildirPath) { $this->maildirPath = $maildirPath; return $this; }

    public function getAgentPath() { return $this->agentPath; }
    public function setAgentPath($agentPath) { $this->agentPath = $agentPath; return $this; }

    public function getSshHostKey() { return $this->sshHostKey; }
    public function setSshHostKey($sshHostKey) { $this->sshHostKey = $sshHostKey; return $this; }

    public function getDeleteSpam() { return $this->deleteSpam; }
    public function setDeleteSpam($deleteSpam) { $this->deleteSpam = $deleteSpam; return $this; }

    public function getAgentDeployed() { return $this->agentDeployed; }
    public function setAgentDeployed($agentDeployed) { $this->agentDeployed = $agentDeployed; return $this; }

    public function getLastScanAt() { return $this->lastScanAt; }
    public function setLastScanAt($lastScanAt) { $this->lastScanAt = $lastScanAt; return $this; }

    public function getLastScanResult() { return $this->lastScanResult; }
    public function setLastScanResult($lastScanResult) { $this->lastScanResult = $lastScanResult; return $this; }

    public function getPluginPasswordHash() { return $this->pluginPasswordHash; }
    public function setPluginPasswordHash($hash) { $this->pluginPasswordHash = $hash; return $this; }

    public function getSpamThreshold(): ?int { return $this->spamThreshold === null ? null : (int)$this->spamThreshold; }
    public function setSpamThreshold(?int $v) { $this->spamThreshold = $v; return $this; }

    public function getQuarantineThreshold(): ?int { return $this->quarantineThreshold === null ? null : (int)$this->quarantineThreshold; }
    public function setQuarantineThreshold(?int $v) { $this->quarantineThreshold = $v; return $this; }

    public function getScoringEnabled(): ?bool { return $this->scoringEnabled === null ? null : (bool)$this->scoringEnabled; }
    public function setScoringEnabled(?bool $v) { $this->scoringEnabled = $v; return $this; }

    public function getDigestEnabled(): ?bool { return $this->digestEnabled === null ? null : (bool)$this->digestEnabled; }
    public function setDigestEnabled(?bool $v) { $this->digestEnabled = $v; return $this; }

    public function getDigestRecipient(): ?string { return $this->digestRecipient; }
    public function setDigestRecipient(?string $v) { $this->digestRecipient = ($v === null || trim($v) === '') ? null : trim($v); return $this; }

    public function getDigestHour(): ?int { return $this->digestHour === null ? null : (int)$this->digestHour; }
    public function setDigestHour(?int $v) { $this->digestHour = $v; return $this; }

    /**
     * Per-mailbox overrides that are set (field => value); empty = the
     * mailbox inherits every global setting.
     *
     * @return array<string, int|bool|string>
     */
    public function getSettingsOverrides(): array
    {
        return array_filter([
            'spam_threshold' => $this->getSpamThreshold(),
            'quarantine_threshold' => $this->getQuarantineThreshold(),
            'scoring_enabled' => $this->getScoringEnabled(),
            'digest_enabled' => $this->getDigestEnabled(),
            'digest_recipient' => $this->getDigestRecipient(),
            'digest_hour' => $this->getDigestHour(),
        ], static fn ($v) => $v !== null);
    }

    public function hasSettingsOverrides(): bool
    {
        return $this->getSettingsOverrides() !== [];
    }

    public function getImapUidValidity() { return $this->imapUidValidity === null ? null : (int)$this->imapUidValidity; }
    public function getImapLastUid() { return $this->imapLastUid === null ? null : (int)$this->imapLastUid; }

    /** @param array{uidvalidity:int, last_uid:int}|null $cursor */
    public function setImapCursor(?array $cursor)
    {
        $this->imapUidValidity = $cursor === null ? null : (int)$cursor['uidvalidity'];
        $this->imapLastUid = $cursor === null ? null : (int)$cursor['last_uid'];
        return $this;
    }

    /**
     * Another server or mailbox: its UIDs mean nothing for the old cursor.
     * Without a cursor the next scan only looks at mail since the last scan.
     */
    private function forgetCursorIfChanged($old, $new)
    {
        if ($old !== null && (string)$old !== (string)$new) {
            $this->imapUidValidity = null;
            $this->imapLastUid = null;
        }
    }

    /** @return array{uidvalidity:int, last_uid:int}|null */
    public function getImapCursor()
    {
        if ($this->imapUidValidity === null || $this->imapLastUid === null) {
            return null;
        }
        return ['uidvalidity' => (int)$this->imapUidValidity, 'last_uid' => (int)$this->imapLastUid];
    }

    /** Set (or with null/'' clear) the Thunderbird plugin password. */
    public function setPluginPassword($plain)
    {
        $this->pluginPasswordHash = ((string)$plain === '') ? null : password_hash((string)$plain, PASSWORD_BCRYPT);
        return $this;
    }

    /**
     * Store a finished scan. The first one after connecting the mailbox is
     * flagged 'initial' so the dashboard leaves it out.
     */
    public function markScanned(array $result)
    {
        if ($this->lastScanAt === null) {
            $result['initial'] = true;
        }
        $this->lastScanAt = new \DateTime();
        $this->lastScanResult = json_encode($result);
        return $this;
    }

    public function getLastScanResultDecoded()
    {
        return $this->lastScanResult ? json_decode($this->lastScanResult, true) : null;
    }
}
