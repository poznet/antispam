<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\PluginReport;
use AntispamBundle\Entity\SharedSpamSignal;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Server side of the Thunderbird plugin: plugin settings (plugin.* keys in the
 * config table), stateless login tokens, per-IP rate limiting and the
 * "learning" part — turning spam / not-spam reports from users into shared
 * feed fingerprints and per-account e-mail rules.
 *
 * Tokens are HMAC-signed with the kernel secret ("<payload>.<signature>"), so
 * no session table is needed; changing the account's plugin password does
 * not revoke issued tokens (they expire after plugin.token_ttl_days), but
 * deleting the account does.
 */
class PluginService
{
    const VERDICT_SPAM = 'spam';
    const VERDICT_HAM = 'ham';

    const DEFAULT_TOKEN_TTL_DAYS = 90;
    const DEFAULT_REPORT_RATE_LIMIT = 120; // per IP per hour
    const LOGIN_RATE_LIMIT = 10;           // failed+successful attempts per IP per 15 min

    /** Upper bound for a submitted (already decoded) message source. */
    const MAX_RAW_BYTES = 4194304; // 4 MiB — the plugin truncates to 700 KiB anyway

    /**
     * Default for plugin.max_upload_kb: the largest message source a plugin
     * sends in one request. Base64 + JSON make the body ~4/3 of it, so 700 KiB
     * stays under nginx's default client_max_body_size of 1 MiB.
     */
    const DEFAULT_MAX_UPLOAD_KB = 700;
    const MIN_MAX_UPLOAD_KB = 64;

    private $em;
    private $config;
    private $cache;
    private $feed;
    private $secret;
    private $crypto;

    public function __construct(EntityManagerInterface $em, CacheItemPoolInterface $cache, SpamSignalService $feed, #[Autowire('%kernel.secret%')] string $secret, ?ConfigService $config = null, ?CryptoService $crypto = null)
    {
        $this->crypto = $crypto;
        $this->em = $em;
        $this->config = $config;
        $this->cache = $cache;
        $this->feed = $feed;
        $this->secret = (string)$secret;
    }

    // --- configuration -----------------------------------------------------

    public function isEnabled()
    {
        return $this->readBool('plugin.enabled', true);
    }

    /** Can users who are not logged in to the plugin report spam? */
    public function isAnonymousReportEnabled()
    {
        return $this->readBool('plugin.anonymous_reports', true);
    }

    /** Can logged-in users have incoming mail checked on arrival? */
    public function isCheckEnabled()
    {
        return $this->readBool('plugin.check_enabled', true);
    }

    /** Do logged-in reports create per-account e-mail blacklist/whitelist rules? */
    public function isLearnRulesEnabled()
    {
        return $this->readBool('plugin.learn_rules', true);
    }

    public function getTokenTtlDays()
    {
        return max(1, $this->readInt('plugin.token_ttl_days', self::DEFAULT_TOKEN_TTL_DAYS));
    }

    public function getReportRateLimit()
    {
        return max(1, $this->readInt('plugin.report_rate_limit', self::DEFAULT_REPORT_RATE_LIMIT));
    }

    /**
     * Largest (decoded) message source the plugins should upload, in bytes -
     * published by /api/plugin/status as max_upload_bytes. Spam reports and
     * checks send at most min(this, 700 KiB); phishing reports send the whole
     * message when it fits. Raise it only together with the body limit of the
     * reverse proxy in front of antispam.
     */
    public function getMaxUploadBytes()
    {
        $kb = $this->readInt('plugin.max_upload_kb', self::DEFAULT_MAX_UPLOAD_KB);
        $max = intdiv(PhishingReportService::MAX_RAW_BYTES, 1024);
        return max(self::MIN_MAX_UPLOAD_KB, min($max, $kb)) * 1024;
    }

    /** Public base URL baked into the downloaded plugin; empty => taken from the request. */
    public function getPublicUrl()
    {
        return rtrim(trim($this->readString('plugin.public_url', '')), '/');
    }

    // --- authentication ----------------------------------------------------

    /**
     * Check plugin credentials for a mailbox. Accepted passwords: the
     * account's dedicated plugin password (set in the panel) or, for IMAP
     * accounts, the IMAP password stored for that mailbox.
     *
     * @return Account|null
     */
    public function authenticate($email, $password)
    {
        $account = $this->findAccount($email);
        if (!$account || (string)$password === '') {
            return null;
        }
        $hash = $account->getPluginPasswordHash();
        if ($hash && password_verify((string)$password, $hash)) {
            return $account;
        }
        if ($account->isImap() && (string)$account->getImapPassword() !== '') {
            try {
                $imapPassword = $this->crypto ? $this->crypto->decrypt($account->getImapPassword()) : $account->getImapPassword();
            } catch (\RuntimeException $e) {
                return null;
            }
            if (hash_equals((string)$imapPassword, (string)$password)) {
                return $account;
            }
        }
        return null;
    }

    /** @return array{token:string, expires_at:int} */
    public function issueToken(Account $account)
    {
        $exp = time() + $this->getTokenTtlDays() * 86400;
        $payload = self::b64(json_encode(['e' => strtolower($account->getEmail()), 'x' => $exp]));
        return ['token' => $payload . '.' . $this->sign($payload), 'expires_at' => $exp];
    }

    /**
     * Resolve a bearer token to its account; null when missing, forged,
     * expired or the account no longer exists.
     *
     * @return Account|null
     */
    public function accountForToken($token)
    {
        $parts = explode('.', (string)$token);
        if (count($parts) !== 2 || !hash_equals($this->sign($parts[0]), $parts[1])) {
            return null;
        }
        $data = json_decode((string)self::unb64($parts[0]), true);
        if (!is_array($data) || empty($data['e']) || (int)($data['x'] ?? 0) < time()) {
            return null;
        }
        return $this->findAccount($data['e']);
    }

    /** @return Account|null */
    public function findAccount($email)
    {
        $email = strtolower(trim((string)$email));
        if ($email === '') {
            return null;
        }
        $qb = $this->em->getRepository(Account::class)->createQueryBuilder('a')
            ->where('LOWER(a.email) = :email')->setParameter('email', $email)
            ->setMaxResults(1);
        return $qb->getQuery()->getOneOrNullResult();
    }

    // --- rate limiting -----------------------------------------------------

    /**
     * Fixed-window counter per bucket + client. Returns false once the limit
     * for the current window is exceeded.
     */
    public function hit($bucket, $client, $limit, $windowSeconds)
    {
        $window = (int)floor(time() / $windowSeconds);
        $item = $this->cache->getItem('antispam_plugin_rl.' . $bucket . '.' . sha1((string)$client) . '.' . $window);
        $count = $item->isHit() ? (int)$item->get() : 0;
        if ($count >= $limit) {
            return false;
        }
        $item->set($count + 1)->expiresAfter($windowSeconds);
        $this->cache->save($item);
        return true;
    }

    // --- learning ----------------------------------------------------------

    /**
     * Learn from a user's verdict on a message.
     *
     * spam: the sender + body fingerprints are recorded in the shared spam
     *       feed (anonymous and logged-in users); for logged-in users the
     *       sender is also added to the account's e-mail blacklist and an
     *       exact whitelist entry for it is dropped.
     * ham:  logged-in users only — the exact blacklist entry for the sender
     *       is dropped and the sender is whitelisted for the account.
     *
     * Every report is logged in antispam_plugin_report (Spambox → Zgłoszenia
     * z wtyczki), kept for PluginReport::RETENTION_DAYS.
     *
     * @return array{verdict:string, sender:string, signals:int, rules:string[]}
     */
    public function learn($raw, $verdict, ?Account $account = null, $clientIp = null)
    {
        $msg = new RawMessageParser($raw);
        $sender = $msg->getFromAddress();
        $result = ['verdict' => $verdict, 'sender' => $sender, 'signals' => 0, 'rules' => []];

        if ($verdict === self::VERDICT_SPAM) {
            $signals = $this->feed->signalsFor($sender, $msg->getBodyText());
            if ($signals) {
                $result['signals'] = $this->feed->record($signals, SharedSpamSignal::ORIGIN_LOCAL);
            }
        }

        if ($account && $sender && $this->isLearnRulesEnabled()) {
            $owner = $account->getEmail();
            if ($verdict === self::VERDICT_SPAM) {
                if ($this->removeExact(EmailWhitelist::class, $owner, 'whitelistemail', $sender)) {
                    $result['rules'][] = 'email_whitelist_removed:' . $sender;
                }
                if (!$this->findExact(EmailBlacklist::class, $owner, 'blacklistemail', $sender)) {
                    $rule = new EmailBlacklist();
                    $rule->setEmail($owner)->setBlacklistemail($sender)
                        ->setPatternType(EmailBlacklist::PATTERN_EXACT)->setCounter(0);
                    $this->em->persist($rule);
                    $result['rules'][] = 'email_blacklist_added:' . $sender;
                }
            } else {
                if ($this->removeExact(EmailBlacklist::class, $owner, 'blacklistemail', $sender)) {
                    $result['rules'][] = 'email_blacklist_removed:' . $sender;
                }
                if (!$this->findExact(EmailWhitelist::class, $owner, 'whitelistemail', $sender)) {
                    $rule = new EmailWhitelist();
                    $rule->setEmail($owner)->setWhitelistemail($sender)
                        ->setPatternType(EmailWhitelist::PATTERN_EXACT)->setCounter(0);
                    $this->em->persist($rule);
                    $result['rules'][] = 'email_whitelist_added:' . $sender;
                }
            }
        }

        $log = new PluginReport();
        $log->setVerdict($verdict)
            ->setAccountEmail($account ? $account->getEmail() : null)
            ->setSender($sender ?: null)
            ->setSubject($msg->getSubject() ?: null)
            ->setClientIp($clientIp ?: null)
            ->setSignals($result['signals'])
            ->setRules($result['rules']);
        $this->em->persist($log);

        $this->em->flush();
        $this->em->getRepository(PluginReport::class)
            ->purgeOlderThan(new \DateTime('-' . PluginReport::RETENTION_DAYS . ' days'));
        return $result;
    }

    private function findExact($class, $owner, $field, $value)
    {
        return $this->em->getRepository($class)->findOneBy([
            'email' => $owner,
            $field => $value,
            'patternType' => 'exact',
        ]);
    }

    private function removeExact($class, $owner, $field, $value)
    {
        $rule = $this->findExact($class, $owner, $field, $value);
        if ($rule) {
            $this->em->remove($rule);
            return true;
        }
        return false;
    }

    // --- helpers -----------------------------------------------------------

    private function sign($payload)
    {
        return self::b64(hash_hmac('sha256', 'antispam-plugin:' . $payload, $this->secret, true));
    }

    private static function b64($bin)
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    private static function unb64($str)
    {
        return base64_decode(strtr($str, '-_', '+/'), true);
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
}
