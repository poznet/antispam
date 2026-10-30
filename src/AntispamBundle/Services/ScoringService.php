<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\ListSetting;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Event\MessageEvent;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Centralizes spam scoring configuration and the ham/quarantine/spam decision.
 *
 * Thresholds are stored in the config table (scoring.*) with sane
 * defaults. The service also writes a SpamScoreLog entry per processed message
 * so admins can audit "why was this flagged".
 */
class ScoringService implements RuntimeCacheInterface
{
    const DEFAULT_SPAM_THRESHOLD = 10;
    const DEFAULT_QUARANTINE_THRESHOLD = 5;

    const DEFAULT_CLAMAV_DSN = 'tcp://127.0.0.1:3310';
    const DEFAULT_CLAMAV_SCORE = 15;
    const DEFAULT_CLAMAV_MAX_SIZE = 26214400; // 25 MiB
    const DEFAULT_CLAMAV_TIMEOUT = 30;

    const DEFAULT_VT_SCORE = 15;
    const DEFAULT_VT_THRESHOLD = 3; // min. engines flagging malicious to act
    const DEFAULT_VT_TIMEOUT = 15;

    const LIST_PROTECTED_DOMAINS = 'impersonation.protected_domains';
    const LIST_VIPS = 'impersonation.vips';
    const LIST_URL_DBL_ZONES = 'url.dbl_zones';
    const LIST_BLOCKED_EXTENSIONS = 'attachment.blocked_extensions';

    private $em;
    private $config;
    private $listCache = [];
    /** Settings of the mailbox being scanned right now (withMailbox()); null = global values. */
    private ?MailboxSettings $mailbox = null;

    public function __construct(EntityManagerInterface $em, ?ConfigService $config = null)
    {
        $this->em = $em;
        $this->config = $config;
    }

    /**
     * Run $fn with the thresholds and the scoring switch of one mailbox
     * (MailboxSettingsResolver builds them: account override -> global).
     * Every consumer that asks this service while $fn runs - pipeline
     * listeners, HeaderAnalyzer caps, the CERT default score, the agent
     * settings export, classify() - gets the mailbox's values. The previous
     * scope is restored afterwards, also when $fn throws.
     */
    public function withMailbox(?MailboxSettings $settings, callable $fn)
    {
        $previous = $this->mailbox;
        $this->mailbox = $settings;
        try {
            return $fn();
        } finally {
            $this->mailbox = $previous;
        }
    }

    /** Settings of the mailbox in scope, or null outside withMailbox(). */
    public function getMailboxSettings(): ?MailboxSettings
    {
        return $this->mailbox;
    }

    /** Effective spam threshold: the mailbox in scope, else the global one. */
    public function getSpamThreshold()
    {
        return $this->mailbox ? $this->mailbox->spamThreshold : $this->getGlobalSpamThreshold();
    }

    public function getQuarantineThreshold()
    {
        return $this->mailbox ? $this->mailbox->quarantineThreshold : $this->getGlobalQuarantineThreshold();
    }

    public function isScoringEnabled()
    {
        return $this->mailbox ? $this->mailbox->scoringEnabled : $this->isGlobalScoringEnabled();
    }

    /** Global value (Ustawienia → Filtr spamu), ignoring any mailbox in scope. */
    public function getGlobalSpamThreshold(): int
    {
        return $this->readInt('scoring.spam_threshold', self::DEFAULT_SPAM_THRESHOLD);
    }

    public function getGlobalQuarantineThreshold(): int
    {
        return $this->readInt('scoring.quarantine_threshold', self::DEFAULT_QUARANTINE_THRESHOLD);
    }

    public function isGlobalScoringEnabled(): bool
    {
        return (bool)$this->readBool('scoring.enabled', true);
    }

    public function isDnsblEnabled()
    {
        return (bool)$this->readBool('scoring.dnsbl_enabled', true);
    }

    /**
     * Full rescan: link domains are not looked up on the URI lists (DBL) nor in
     * Google Safe Browsing - DNS / HTTP per message was most of a 30 000-message
     * rescan. The other link checks, the CERT list and the shared feed stay.
     * DNSBL (connecting IP) is skipped in a rescan always.
     */
    public function isRescanUrlLookupSkipped(): bool
    {
        return (bool)$this->readBool('rescan.skip_url_lookups', true);
    }

    public function isHeaderCheckEnabled()
    {
        return (bool)$this->readBool('scoring.header_check_enabled', true);
    }

    public function isLoggingEnabled()
    {
        return (bool)$this->readBool('scoring.log_enabled', true);
    }

    /**
     * ClamAV attachment scanning is opt-in: it stays disabled until an admin
     * enables it and points it at a reachable clamd daemon.
     */
    public function isClamavEnabled()
    {
        return (bool)$this->readBool('scoring.clamav_enabled', false);
    }

    public function getClamavDsn()
    {
        return $this->readString('scoring.clamav_dsn', self::DEFAULT_CLAMAV_DSN);
    }

    public function getClamavScore()
    {
        return $this->readInt('scoring.clamav_score', self::DEFAULT_CLAMAV_SCORE);
    }

    public function getClamavMaxSize()
    {
        return $this->readInt('scoring.clamav_max_size', self::DEFAULT_CLAMAV_MAX_SIZE);
    }

    public function getClamavTimeout()
    {
        return $this->readInt('scoring.clamav_timeout', self::DEFAULT_CLAMAV_TIMEOUT);
    }

    /**
     * VirusTotal attachment lookup is opt-in: it stays disabled until an admin
     * enables it and provides an API key.
     */
    public function isVirusTotalEnabled()
    {
        return (bool)$this->readBool('scoring.vt_enabled', false);
    }

    public function getVirusTotalApiKey()
    {
        return trim($this->readString('scoring.vt_api_key', ''));
    }

    public function getVirusTotalScore()
    {
        return $this->readInt('scoring.vt_score', self::DEFAULT_VT_SCORE);
    }

    /**
     * Minimum number of VirusTotal engines flagging a file as malicious before
     * it is treated as a hit (guards against single-engine false positives).
     */
    public function getVirusTotalThreshold()
    {
        return max(1, $this->readInt('scoring.vt_threshold', self::DEFAULT_VT_THRESHOLD));
    }

    public function getVirusTotalTimeout()
    {
        return $this->readInt('scoring.vt_timeout', self::DEFAULT_VT_TIMEOUT);
    }

    /**
     * Impersonation / BEC protection (VIP display names, lookalike domains,
     * internal-domain spoofing). On by default: without protected domains or
     * VIPs configured only the account's own domain is guarded.
     */
    public function isImpersonationEnabled()
    {
        return (bool)$this->readBool('impersonation.enabled', true);
    }

    /**
     * Protected domains: the configured list plus the account's own domain
     * (unless it is a free-mail provider or auto-protection is switched off).
     */
    public function getProtectedDomains($accountEmail = null)
    {
        $domains = ImpersonationAnalyzer::parseDomains((string)$this->readList(self::LIST_PROTECTED_DOMAINS, ''));
        if ($accountEmail && $this->isProtectOwnDomain()) {
            $own = DomainHelper::normalize(substr(strrchr((string)$accountEmail, '@') ?: '', 1));
            if ($own !== '' && !DomainHelper::isFreemail($own) && !in_array($own, $domains, true)) {
                $domains[] = $own;
            }
        }
        return $domains;
    }

    public function isProtectOwnDomain()
    {
        return (bool)$this->readBool('impersonation.protect_own_domain', true);
    }

    public function getVipList()
    {
        return (string)$this->readList(self::LIST_VIPS, '');
    }

    public function getImpersonationScores()
    {
        $out = [];
        foreach (ImpersonationAnalyzer::DEFAULT_SCORES as $k => $default) {
            $out[$k] = $this->readInt('impersonation.' . $k . '_score', $default);
        }
        return $out;
    }

    /**
     * Link protection (URL heuristics, URI block lists, Safe Browsing).
     */
    public function isUrlCheckEnabled()
    {
        return (bool)$this->readBool('url.enabled', true);
    }

    public function getUrlDblZonesText()
    {
        $raw = $this->readList(self::LIST_URL_DBL_ZONES, null);
        if ($raw === null) {
            $raw = implode("\n", array_map(function ($z) {
                return $z['zone'] . ' ' . $z['score'];
            }, UrlAnalyzer::DEFAULT_CONFIG['dbl_zones']));
        }
        return (string)$raw;
    }

    public function getUrlConfig()
    {
        $d = UrlAnalyzer::DEFAULT_CONFIG;
        return [
            'mismatch_score' => $this->readInt('url.mismatch_score', $d['mismatch_score']),
            'ip_score' => $this->readInt('url.ip_score', $d['ip_score']),
            'shortener_score' => $this->readInt('url.shortener_score', $d['shortener_score']),
            'punycode_score' => $this->readInt('url.punycode_score', $d['punycode_score']),
            'dbl_enabled' => (bool)$this->readBool('url.dbl_enabled', $d['dbl_enabled']),
            'dbl_zones' => UrlAnalyzer::parseZones($this->getUrlDblZonesText()),
            'max_domains' => $this->readInt('url.max_domains', $d['max_domains']),
            'gsb_enabled' => (bool)$this->readBool('url.gsb_enabled', $d['gsb_enabled']),
            'gsb_api_key' => trim($this->readString('url.gsb_api_key', '')),
            'gsb_score' => $this->readInt('url.gsb_score', $d['gsb_score']),
            'timeout' => $this->readInt('url.timeout', $d['timeout']),
        ];
    }

    /**
     * Attachment policy (blocked types, double extensions, macros, encrypted
     * archives). On by default - it needs no external service.
     */
    public function isAttachmentPolicyEnabled()
    {
        return (bool)$this->readBool('attachment.policy_enabled', true);
    }

    public function getBlockedExtensionsText()
    {
        $raw = $this->readList(self::LIST_BLOCKED_EXTENSIONS, null);
        return $raw === null ? implode(', ', AttachmentPolicyAnalyzer::DEFAULT_BLOCKED) : (string)$raw;
    }

    public function getAttachmentPolicyConfig()
    {
        $out = ['blocked_extensions' => AttachmentPolicyAnalyzer::parseExtensions($this->getBlockedExtensionsText())];
        foreach (AttachmentPolicyAnalyzer::DEFAULT_SCORES as $k => $default) {
            $out[$k] = $this->readInt('attachment.' . $k, $default);
        }
        return $out;
    }

    public function setListSetting($name, $value)
    {
        $this->em->getRepository(ListSetting::class)->setValue($name, $value);
        unset($this->listCache[$name]);
    }

    /**
     * Scanning settings in the shape the Maildir agent expects in the
     * `settings` section of its import-rules payload. Lists are flattened to
     * newline-separated strings (the agent stores settings as key/value text).
     * The set is complete: the agent replaces its settings with it, keys left
     * out fall back to the agent's defaults (see docs/agent.md).
     */
    public function exportAgentSettings($accountEmail = null)
    {
        $url = $this->getUrlConfig();
        $att = $this->getAttachmentPolicyConfig();
        $imp = $this->getImpersonationScores();

        return [
            // Thresholds and global switches: the agent's scan and its
            // apply-blacklist pass decide like the web pipeline.
            'scoring_enabled' => $this->isScoringEnabled(),
            'spam_threshold' => $this->getSpamThreshold(),
            'quarantine_threshold' => $this->getQuarantineThreshold(),
            'dnsbl_enabled' => $this->isDnsblEnabled(),
            'header_check_enabled' => $this->isHeaderCheckEnabled(),
            'impersonation_enabled' => $this->isImpersonationEnabled(),
            'impersonation_protected_domains' => implode("\n", $this->getProtectedDomains($accountEmail)),
            'impersonation_vips' => $this->getVipList(),
            'impersonation_vip_score' => $imp['vip'],
            'impersonation_lookalike_score' => $imp['lookalike'],
            'impersonation_embedded_score' => $imp['embedded'],
            'impersonation_internal_score' => $imp['internal'],
            'cert_enabled' => (bool)$this->readBool('cert.enabled', false),
            'cert_score' => $this->readInt('cert.score', $this->getSpamThreshold()),
            'cert_url' => $this->readString('cert.url', ''),
            'url_enabled' => $this->isUrlCheckEnabled(),
            'url_mismatch_score' => $url['mismatch_score'],
            'url_ip_score' => $url['ip_score'],
            'url_shortener_score' => $url['shortener_score'],
            'url_punycode_score' => $url['punycode_score'],
            'url_dbl_enabled' => $url['dbl_enabled'],
            'url_dbl_zones' => $this->getUrlDblZonesText(),
            'url_max_domains' => $url['max_domains'],
            'url_gsb_enabled' => $url['gsb_enabled'],
            'url_gsb_api_key' => $url['gsb_api_key'],
            'url_gsb_score' => $url['gsb_score'],
            'url_timeout' => $url['timeout'],
            'attachment_policy_enabled' => $this->isAttachmentPolicyEnabled(),
            'attachment_blocked_extensions' => implode(',', $att['blocked_extensions']),
            'attachment_blocked_score' => $att['blocked_score'],
            'attachment_double_ext_score' => $att['double_ext_score'],
            'attachment_mismatch_score' => $att['mismatch_score'],
            'attachment_macro_score' => $att['macro_score'],
            'attachment_encrypted_score' => $att['encrypted_score'],
            'clamav_enabled' => $this->isClamavEnabled(),
            'clamav_dsn' => $this->getClamavDsn(),
            'clamav_score' => $this->getClamavScore(),
            'clamav_max_size' => $this->getClamavMaxSize(),
            'clamav_timeout' => $this->getClamavTimeout(),
            'vt_enabled' => $this->isVirusTotalEnabled(),
            'vt_api_key' => $this->getVirusTotalApiKey(),
            'vt_score' => $this->getVirusTotalScore(),
            'vt_threshold' => $this->getVirusTotalThreshold(),
            'vt_timeout' => $this->getVirusTotalTimeout(),
        ];
    }

    /**
     * Apply the final spam/quarantine/ham decision to the event based on the
     * accumulated score and persist a SpamScoreLog entry.
     */
    public function decide(MessageEvent $event, array $reasons, $sender = null, $subject = null)
    {
        $score = $event->getSpamscore();
        $decision = $this->classify($score, $event->isSpam(), $event->isWhitelist());
        if ($decision === SpamScoreLog::DECISION_SPAM) {
            $event->setSpam(true);
        }

        // Quarantine/spam get their outcome once the message has been moved.
        $outcome = in_array($decision, [SpamScoreLog::DECISION_HAM, SpamScoreLog::DECISION_WHITELISTED], true)
            ? SpamScoreLog::OUTCOME_NONE : null;
        $event->setScoreLog($this->logDecision($event->getEmail(), $score, $decision, $reasons, $sender, $subject, $event->isRescan() ? SpamScoreLog::SOURCE_RESCAN : SpamScoreLog::SOURCE_SCAN, $outcome, $event->isInitialScan()));

        return $decision;
    }

    /**
     * Turn a score into ham/quarantine/spam/whitelisted. Shared by the IMAP
     * pipeline and the raw-message scanner used by the Thunderbird plugin.
     */
    public function classify($score, $forcedSpam = false, $whitelisted = false)
    {
        if ($whitelisted) {
            return SpamScoreLog::DECISION_WHITELISTED;
        }
        if ($forcedSpam || $score >= $this->getSpamThreshold()) {
            return SpamScoreLog::DECISION_SPAM;
        }
        if ($score >= $this->getQuarantineThreshold()) {
            return SpamScoreLog::DECISION_QUARANTINE;
        }
        return SpamScoreLog::DECISION_HAM;
    }

    /**
     * Persist a SpamScoreLog entry when decision logging is enabled.
     *
     * @return SpamScoreLog|null null when logging is disabled
     */
    public function logDecision($accountEmail, $score, $decision, array $reasons, $sender = null, $subject = null, $source = null, $outcome = null, $initialScan = false)
    {
        if (!$this->isLoggingEnabled()) {
            return null;
        }
        $log = new SpamScoreLog();
        $log->setAccountEmail($accountEmail)
            ->setSender($sender)
            ->setSubject($subject)
            ->setScore($score)
            ->setDecision($decision)
            ->setReasons($reasons)
            ->setSource($source)
            ->setOutcome($outcome)
            ->setInitialScan($initialScan);
        $this->em->persist($log);
        $this->em->flush();
        return $log;
    }

    /** Record where a logged message ended up (OUTCOME_*); no-op without a log entry. */
    public function recordOutcome(?SpamScoreLog $log, $outcome)
    {
        if ($log === null) {
            return;
        }
        $log->setOutcome($outcome);
        $this->em->flush();
    }

    private function readList($name, $default)
    {
        if (!array_key_exists($name, $this->listCache)) {
            try {
                $this->listCache[$name] = $this->em->getRepository(ListSetting::class)->getValue($name);
            } catch (\Throwable $e) {
                $this->listCache[$name] = null; // table not created yet
            }
        }
        return $this->listCache[$name] === null ? $default : $this->listCache[$name];
    }

    private function readInt($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (int)$v;
    }

    private function readString($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (string)$v;
    }

    private function readBool($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        if ($v === null || $v === '') return $default;
        if (is_bool($v)) return $v;
        return in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }

    public function clearRuntimeCache(): void
    {
        $this->listCache = [];
    }
}
