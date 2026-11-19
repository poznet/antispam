<?php

namespace AntispamBundle\Services;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Network facts about a sender domain for the complex rules
 * (docs/complex-rules.md#sender-domain-lookups):
 *
 *  - MX hosts of the From domain (DNS) and the mail provider they belong to
 *    (google, microsoft, home.pl, ...; classifyMx());
 *  - age of the registered domain in days: RDAP (rdap.org bootstrap, which
 *    redirects to the registry), with a WHOIS (port 43) fallback for
 *    registries without RDAP - the server comes from whois.iana.org.
 *
 * Results are cached (MX 1 day, age 7 days, failures 6 hours) in the app
 * cache pool, so a domain costs one lookup per period, not one per message.
 * Every lookup is best effort: a timeout or an unknown answer is "no value"
 * - conditions on it do not match (negated ones do), it never fails a scan.
 * Off with complex.lookups = 0 (Reguły złożone page).
 *
 * The Maildir agent has its own copy (complexLookup*() in antispam-agent.php).
 */
class SenderIntelService
{
    /** Provider slugs (classifyMx()); "other" = MX present, unknown; "none" = no MX. */
    public const PROVIDER_SLUGS = ['google', 'microsoft', 'zoho', 'proton', 'yahoo', 'icloud', 'yandex', 'mailru', 'fastmail',
        'ovh', 'homepl', 'nazwapl', 'cyberfolks', 'lh', 'zenbox', 'wp', 'onet', 'interia', 'o2',
        'mimecast', 'proofpoint', 'barracuda', 'other', 'none'];

    /** Host suffix => provider. Checked against each MX host (most specific first). */
    private const MX_PROVIDERS = [
        'google.com' => 'google', 'googlemail.com' => 'google', 'smtp.goog' => 'google',
        'mail.protection.outlook.com' => 'microsoft', 'outlook.com' => 'microsoft', 'hotmail.com' => 'microsoft', 'microsoft.com' => 'microsoft',
        'zoho.com' => 'zoho', 'zoho.eu' => 'zoho', 'zohomail.com' => 'zoho',
        'protonmail.ch' => 'proton', 'proton.me' => 'proton',
        'yahoodns.net' => 'yahoo', 'icloud.com' => 'icloud', 'me.com' => 'icloud',
        'yandex.net' => 'yandex', 'yandex.ru' => 'yandex', 'mail.ru' => 'mailru',
        'messagingengine.com' => 'fastmail',
        'ovh.net' => 'ovh', 'ovh.com' => 'ovh',
        'home.pl' => 'homepl', 'nazwa.pl' => 'nazwapl', 'cyberfolks.pl' => 'cyberfolks', 'cyber-folks.pl' => 'cyberfolks',
        'lh.pl' => 'lh', 'zenbox.pl' => 'zenbox', 'wp.pl' => 'wp', 'o2.pl' => 'o2', 'onet.pl' => 'onet', 'opoczta.pl' => 'onet',
        'poczta.onet.pl' => 'onet', 'interia.pl' => 'interia', 'interia.eu' => 'interia',
        'mimecast.com' => 'mimecast', 'pphosted.com' => 'proofpoint', 'ppe-hosted.com' => 'proofpoint',
        'barracudanetworks.com' => 'barracuda', 'ess.barracudanetworks.com' => 'barracuda',
    ];

    private const TTL_MX = 86400;
    private const TTL_AGE = 604800;
    private const TTL_FAIL = 21600;
    private const TIMEOUT = 4;
    /** Per-process memo (a scan sees the same domain many times). */
    private array $memo = [];

    /**
     * @param callable|null $mxResolver fn(string $domain): string[] (tests)
     * @param callable|null $ageResolver fn(string $domain): ?int (tests)
     */
    public function __construct(
        private ?CacheItemPoolInterface $cache = null,
        private ?ConfigService $config = null,
        private $mxResolver = null,
        private $ageResolver = null,
    ) {
    }

    public function isEnabled(): bool
    {
        if ($this->config === null) {
            return true;
        }
        $v = $this->config->get('complex.lookups');
        return $v === null || !in_array((string)$v, ['0', 'false'], true);
    }

    /** @return string[] MX hosts of the domain, lowest preference first ([] = none / lookup failed) */
    public function mxHosts(string $domain): array
    {
        $domain = DomainHelper::normalize($domain);
        if ($domain === '' || DomainHelper::isIp($domain) || !$this->isEnabled()) {
            return [];
        }
        return $this->mxLookup($domain) ?? [];
    }

    /** null = the lookup failed (timeout, SERVFAIL) - unlike [] = no MX. */
    private function mxLookup(string $domain): ?array
    {
        return $this->cached('mx', $domain, self::TTL_MX, function () use ($domain) {
            $hosts = $this->mxResolver ? ($this->mxResolver)($domain) : self::resolveMx($domain);
            return $hosts === null ? [null, false] : [array_values(array_map('strval', (array)$hosts)), true];
        });
    }

    /** Provider slug of the domain's mail ('none' without MX, '' when unknown or lookups are off). */
    public function mxProvider(string $domain): string
    {
        $domain = DomainHelper::normalize($domain);
        if ($domain === '' || DomainHelper::isIp($domain) || !$this->isEnabled()) {
            return '';
        }
        $hosts = $this->mxLookup($domain);
        return $hosts === null ? '' : self::classifyMx($hosts);
    }

    /** Age of the registered domain in days, null when unknown. */
    public function domainAgeDays(string $domain): ?int
    {
        $reg = DomainHelper::registrable($domain);
        if ($reg === '' || DomainHelper::isIp($reg) || strpos($reg, '.') === false || !$this->isEnabled()) {
            return null;
        }
        $created = $this->cached('age', $reg, self::TTL_AGE, function () use ($reg) {
            if ($this->ageResolver) {
                $days = ($this->ageResolver)($reg);
                return [$days === null ? null : time() - (int)$days * 86400, $days !== null];
            }
            $ts = self::rdapCreated($reg) ?? self::whoisCreated($reg);
            return [$ts, $ts !== null];
        });
        return $created === null ? null : max(0, intdiv(time() - (int)$created, 86400));
    }

    public static function classifyMx(array $hosts): string
    {
        if (!$hosts) {
            return 'none';
        }
        foreach ($hosts as $host) {
            $host = rtrim(strtolower((string)$host), '.');
            foreach (self::MX_PROVIDERS as $suffix => $slug) {
                if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                    return $slug;
                }
            }
        }
        return 'other';
    }

    /** @return string[]|null null when the lookup failed */
    public static function resolveMx(string $domain): ?array
    {
        if (!function_exists('dns_get_record')) {
            return null;
        }
        $records = @dns_get_record($domain . '.', DNS_MX);
        if ($records === false) {
            return null;
        }
        usort($records, fn ($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));
        $out = [];
        foreach ($records as $r) {
            $t = rtrim(strtolower((string)($r['target'] ?? '')), '.');
            if ($t !== '') {
                $out[] = $t;
            }
        }
        return array_values(array_unique($out));
    }

    /** Registration timestamp from RDAP (events[eventAction=registration]). */
    public static function rdapCreated(string $domain): ?int
    {
        $body = self::httpGet('https://rdap.org/domain/' . rawurlencode($domain));
        $data = $body !== null ? json_decode($body, true) : null;
        foreach ((array)($data['events'] ?? []) as $event) {
            if (is_array($event) && ($event['eventAction'] ?? '') === 'registration' && ($ts = strtotime((string)($event['eventDate'] ?? '')))) {
                return $ts;
            }
        }
        return null;
    }

    /** Creation date from WHOIS: the TLD's server from whois.iana.org, then the domain there. */
    public static function whoisCreated(string $domain): ?int
    {
        $tld = substr($domain, strrpos($domain, '.') + 1);
        $iana = self::whois('whois.iana.org', $tld);
        if ($iana === null || !preg_match('/^whois:\s*(\S+)/mi', $iana, $m)) {
            return null;
        }
        $answer = self::whois($m[1], $domain);
        return $answer === null ? null : self::parseWhoisCreated($answer);
    }

    public static function parseWhoisCreated(string $text): ?int
    {
        if (preg_match('/^\s*(?:creation date|created|created on|registered|registered on|registration time|domain registration date|record created)\s*[:.]+\s*(.+)$/mi', $text, $m)) {
            $value = trim(preg_replace('/\s+\(.*\)$/', '', $m[1]));
            $value = preg_replace('/^(\d{4})\.(\d{2})\.(\d{2})/', '$1-$2-$3', $value);
            $ts = strtotime($value);
            return $ts ?: null;
        }
        return null;
    }

    private static function whois(string $server, string $query): ?string
    {
        if (!preg_match('/^[a-z0-9.-]+$/i', $server)) {
            return null;
        }
        $fp = @fsockopen($server, 43, $errno, $errstr, self::TIMEOUT);
        if (!$fp) {
            return null;
        }
        stream_set_timeout($fp, self::TIMEOUT);
        fwrite($fp, $query . "\r\n");
        $out = '';
        while (!feof($fp) && strlen($out) < 65536) {
            $chunk = fread($fp, 8192);
            if ($chunk === false || ($chunk === '' && (stream_get_meta_data($fp)['timed_out'] ?? false))) {
                break;
            }
            $out .= $chunk;
        }
        fclose($fp);
        return $out === '' ? null : $out;
    }

    private static function httpGet(string $url): ?string
    {
        $ctx = stream_context_create(['http' => [
            'timeout' => self::TIMEOUT,
            'follow_location' => 1,
            'max_redirects' => 3,
            'ignore_errors' => false,
            'header' => "Accept: application/rdap+json\r\nUser-Agent: antispam-pancernapanda\r\n",
        ]]);
        $body = @file_get_contents($url, false, $ctx, 0, 262144);
        return $body === false ? null : $body;
    }

    /** @param callable(): array{0:mixed, 1:bool} $compute [value, ok]; failures are kept TTL_FAIL */
    private function cached(string $kind, string $key, int $ttl, callable $compute)
    {
        $memoKey = $kind . ':' . $key;
        if (array_key_exists($memoKey, $this->memo)) {
            return $this->memo[$memoKey];
        }
        $item = null;
        if ($this->cache) {
            try {
                $item = $this->cache->getItem('antispam_intel.' . $kind . '.' . sha1($key));
                if ($item->isHit()) {
                    return $this->memo[$memoKey] = $item->get();
                }
            } catch (\Throwable $e) {
                $item = null;
            }
        }
        try {
            [$value, $ok] = $compute();
        } catch (\Throwable $e) {
            [$value, $ok] = [null, false];
        }
        if ($item) {
            try {
                $this->cache->save($item->set($value)->expiresAfter($ok ? $ttl : self::TTL_FAIL));
            } catch (\Throwable $e) {}
        }
        if (count($this->memo) > 5000) {
            $this->memo = [];
        }
        return $this->memo[$memoKey] = $value;
    }
}
