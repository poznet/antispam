<?php

namespace AntispamBundle\Services;

/**
 * Link protection (inspired by Barracuda Link Protection / intent analysis).
 * Extracts URLs from the message body and scores:
 *
 *   - anchor text showing one domain while the href points to another
 *   - links to raw IP addresses
 *   - URL shorteners hiding the real destination
 *   - punycode (IDN) hosts, the usual vehicle for homograph phishing
 *   - domains listed on URI block lists (Spamhaus DBL, SURBL, URIBL)
 *   - URLs flagged by Google Safe Browsing (optional, needs an API key)
 *
 * Every rule fires at most once per message so a long newsletter can't stack
 * points. DNS and HTTP failures are "no opinion", never a penalty.
 */
class UrlAnalyzer
{
    const DEFAULT_CONFIG = [
        'mismatch_score' => 3,
        'ip_score' => 3,
        'shortener_score' => 2,
        'punycode_score' => 3,
        'dbl_enabled' => true,
        'dbl_zones' => [['zone' => 'dbl.spamhaus.org', 'score' => 6], ['zone' => 'multi.surbl.org', 'score' => 6]],
        'max_domains' => 20,
        'gsb_enabled' => false,
        'gsb_api_key' => '',
        'gsb_score' => 10,
        'timeout' => 10,
    ];

    const MAX_BODY = 1048576; // only the first 1 MiB of a body is inspected

    private static $shorteners = [
        'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 't.ly',
        'tiny.cc', 's.id', 'v.gd', 'bl.ink', 'short.io', 'shorte.st', 'adf.ly',
        'qrco.de', 'tiny.one', 'urlz.fr', 'x.co',
    ];

    /** @var callable|null fn(string $fqdn): string[]|null list of A records (null = DNS error) */
    private $resolver;
    /** @var callable|null fn(array $urls, string $key, int $timeout): string[] flagged urls */
    private $safeBrowsing;

    private $dnsCache = [];
    /** @var array<string, int> zone => failed or slow lookups (circuit breaker, see DnsblService) */
    private $dnsFailures = [];

    public function __construct(?callable $resolver = null, ?callable $safeBrowsing = null)
    {
        $this->resolver = $resolver;
        $this->safeBrowsing = $safeBrowsing;
    }

    /**
     * Parse "zone score" lines (or "zone|score") into DNSBL zone definitions.
     */
    public static function parseZones($lines, $defaultScore = 6)
    {
        if (!is_array($lines)) {
            $lines = preg_split('/\r?\n/', (string)$lines);
        }
        $zones = [];
        foreach ($lines as $line) {
            $line = trim((string)$line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $parts = preg_split('/[\s|,;]+/', $line);
            $zone = strtolower(trim($parts[0], '.'));
            if (!preg_match('/^[a-z0-9.\-]+\.[a-z]{2,}$/', $zone)) {
                continue;
            }
            $zones[] = ['zone' => $zone, 'score' => isset($parts[1]) && is_numeric($parts[1]) ? (int)$parts[1] : (int)$defaultScore];
        }
        return $zones;
    }

    /**
     * @return array list of ['href' => string, 'text' => string|null]
     */
    public static function extractLinks($html, $text)
    {
        $links = [];
        $html = substr((string)$html, 0, self::MAX_BODY);
        $text = substr((string)$text, 0, self::MAX_BODY);

        if ($html !== '' && preg_match_all('~<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))[^>]*>(.*?)</a\s*>~is', $html, $m, PREG_SET_ORDER)) {
            foreach ($m as $a) {
                $href = $a[1] !== '' ? $a[1] : ($a[2] !== '' ? $a[2] : ($a[3] ?? ''));
                $href = trim(html_entity_decode($href, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                $label = trim(html_entity_decode(strip_tags($a[4]), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                if ($href !== '') {
                    $links[] = ['href' => $href, 'text' => $label];
                }
            }
        }
        foreach ([$text, $html] as $blob) {
            if ($blob !== '' && preg_match_all('~\bhttps?://[^\s<>"\'()\[\]{}]+~i', $blob, $m)) {
                foreach ($m[0] as $u) {
                    $links[] = ['href' => rtrim(html_entity_decode($u, ENT_QUOTES | ENT_HTML5, 'UTF-8'), '.,;:!?'), 'text' => null];
                }
            }
        }
        return $links;
    }

    public static function hostOf($url)
    {
        $url = trim((string)$url);
        if (!preg_match('~^https?://~i', $url)) {
            return '';
        }
        $host = parse_url($url, PHP_URL_HOST);
        return $host ? DomainHelper::normalize($host) : '';
    }

    /**
     * @return array ['score' => int, 'reasons' => [...], 'domains' => string[]]
     */
    public function analyze($html, $text, array $config = [])
    {
        $config = array_merge(self::DEFAULT_CONFIG, $config);
        $links = self::extractLinks($html, $text);
        $score = 0;
        $reasons = [];
        $fired = [];
        $domains = [];
        $urls = [];

        $add = function ($key, $rule, $points, array $extra = []) use (&$score, &$reasons, &$fired) {
            if (isset($fired[$key]) || (int)$points <= 0) {
                return;
            }
            $fired[$key] = true;
            $score += (int)$points;
            $reasons[] = array_merge(['rule' => $rule, 'score' => (int)$points], $extra);
        };

        foreach ($links as $link) {
            $host = self::hostOf($link['href']);
            if ($host === '') {
                continue;
            }
            $urls[$link['href']] = true;

            if (DomainHelper::isIp($host)) {
                $add('ip', 'url_ip_host:' . $host, $config['ip_score']);
                continue;
            }
            $reg = DomainHelper::registrable($host);
            $domains[$reg] = true;

            if (in_array($host, self::$shorteners, true) || in_array($reg, self::$shorteners, true)) {
                $add('short', 'url_shortener:' . $reg, $config['shortener_score']);
            }
            if (strpos($host, 'xn--') !== false) {
                $add('puny', 'url_punycode:' . $host, $config['punycode_score'], ['unicode' => DomainHelper::toUnicode($host)]);
            }
            if ($link['text'] !== null && $link['text'] !== '') {
                $shown = self::domainInText($link['text']);
                if ($shown !== '' && DomainHelper::registrable($shown) !== $reg) {
                    $add('mismatch', 'url_text_mismatch:' . $shown . '->' . $reg, $config['mismatch_score']);
                }
            }
        }

        $domains = array_slice(array_keys($domains), 0, max(1, (int)$config['max_domains']));

        if (!empty($config['dbl_enabled']) && $config['dbl_zones']) {
            foreach ($config['dbl_zones'] as $z) {
                foreach ($domains as $d) {
                    if ($this->isDblListed($d, $z['zone'])) {
                        $add('dbl:' . $z['zone'], 'url_dbl:' . $z['zone'], $z['score'], ['domain' => $d]);
                        break;
                    }
                }
            }
        }

        if (!empty($config['gsb_enabled']) && trim((string)$config['gsb_api_key']) !== '' && $urls) {
            $lookup = $this->safeBrowsing ?: [self::class, 'safeBrowsingLookup'];
            $flagged = call_user_func($lookup, array_slice(array_keys($urls), 0, 50), trim((string)$config['gsb_api_key']), (int)$config['timeout']);
            if ($flagged) {
                $add('gsb', 'url_safebrowsing', $config['gsb_score'], ['url' => substr($flagged[0], 0, 200)]);
            }
        }

        return ['score' => $score, 'reasons' => $reasons, 'domains' => $domains];
    }

    /**
     * Domain shown in link text, e.g. "www.paypal.com" or "https://bank.pl/login".
     */
    private static function domainInText($text)
    {
        $text = trim($text);
        if (strlen($text) > 200 || preg_match('/\s/', $text)) {
            return '';
        }
        if (preg_match('~^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:/?#].*)?$~i', $text, $m)) {
            return DomainHelper::normalize($m[1]);
        }
        return '';
    }

    private function isDblListed($domain, $zone)
    {
        $key = $domain . '|' . $zone;
        if (!array_key_exists($key, $this->dnsCache)) {
            if (($this->dnsFailures[$zone] ?? 0) >= DnsblService::MAX_FAILURES) {
                return false; // zone keeps failing: skip it for the rest of the run
            }
            $started = microtime(true);
            $records = $this->resolver
                ? call_user_func($this->resolver, $domain . '.' . $zone)
                : DnsblService::lookupA($domain . '.' . $zone);
            if ($records === null || microtime(true) - $started > DnsblService::SLOW_LOOKUP_SECONDS) {
                $this->dnsFailures[$zone] = ($this->dnsFailures[$zone] ?? 0) + 1;
            }
            $listed = false;
            foreach ((array)$records as $ip) {
                // 127.0.0.1 = query refused (URIBL), 127.255.255.x = error codes
                // (Spamhaus via public resolvers) - neither means "listed".
                if (DnsblService::isListingAddress($ip)) {
                    $listed = true;
                    break;
                }
            }
            $this->dnsCache[$key] = $listed;
        }
        return $this->dnsCache[$key];
    }

    public static function resolveA($fqdn)
    {
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($fqdn, DNS_A);
            return is_array($records) ? array_filter(array_column($records, 'ip')) : [];
        }
        $ip = @gethostbyname($fqdn);
        return ($ip && $ip !== $fqdn) ? [$ip] : [];
    }

    /**
     * Google Safe Browsing v4 Lookup API.
     *
     * @return string[] the URLs reported as threats (empty on any error)
     */
    public static function safeBrowsingLookup(array $urls, $apiKey, $timeout = 10)
    {
        if (!$urls || !function_exists('curl_init')) {
            return [];
        }
        $payload = [
            'client' => ['clientId' => 'pancernapanda-antispam', 'clientVersion' => '1.0'],
            'threatInfo' => [
                'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes' => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries' => array_map(function ($u) { return ['url' => $u]; }, array_values($urls)),
            ],
        ];
        $ch = curl_init('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode($apiKey));
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($payload),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false || $status !== 200) {
            return [];
        }
        $data = json_decode($body, true);
        $out = [];
        foreach ((array)($data['matches'] ?? []) as $match) {
            if (!empty($match['threat']['url'])) {
                $out[] = $match['threat']['url'];
            }
        }
        return $out;
    }
}
