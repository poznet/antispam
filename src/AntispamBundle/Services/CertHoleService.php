<?php

namespace AntispamBundle\Services;

use Doctrine\DBAL\ArrayParameterType;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Filter based on the CERT Polska "Lista Ostrzeżeń" (https://hole.cert.pl), the
 * list of phishing / malware domains that Polish ISPs block. The list is
 * downloaded by `antispam:cert:sync` into the antispam_cert_domain table; a
 * message scores when its sender domain (From, Reply-To, Return-Path) or any
 * link domain in the body equals a listed domain or is a subdomain of one.
 */
class CertHoleService

{
    const DEFAULT_URL = 'https://hole.cert.pl/domains/v2/domains.txt';

    /** Download cap: the real list is ~2.5 MB, anything near this is not the list. */
    const MAX_BYTES = 50 * 1024 * 1024;

    /** A new list smaller than this share of the current one is refused. */
    const MIN_RATIO = 0.5;

    /** A list with fewer domains is never accepted (an error page, a truncated file). */
    const MIN_ROWS = 100;

    const INSERT_BATCH = 1000;
    const MAX_LINK_HOSTS = 100;

    /** cert.last_error is clipped to this many characters. */
    const MAX_ERROR_CHARS = 1000;

    private $em;
    private $config;

    public function __construct(EntityManagerInterface $em, ConfigService $config)
    {
        $this->em = $em;
        $this->config = $config;
    }

    // --- configuration / status ---------------------------------------------

    public function isEnabled()
    {
        return in_array(strtolower((string)$this->config->get('cert.enabled')), ['1', 'true', 'yes', 'on'], true);
    }

    /** Points per matching message; defaults to the spam threshold so one hit is enough. */
    public function getScore($spamThreshold = 10)
    {
        $v = $this->config->get('cert.score');
        return ($v === null || $v === '') ? max(1, (int)$spamThreshold) : max(1, (int)$v);
    }

    public function getUrl()
    {
        $url = trim((string)$this->config->get('cert.url'));
        // https only: no file://, gopher:// ... from a tampered setting.
        return stripos($url, 'https://') === 0 ? $url : self::DEFAULT_URL;
    }

    /** @return array{last_sync_at:?string, last_attempt_at:?string, count:int, last_error:string} */
    public function getStatus()
    {
        return [
            'last_sync_at' => $this->config->get('cert.last_sync_at') ?: null,
            'last_attempt_at' => $this->config->get('cert.last_attempt_at') ?: null,
            'count' => (int)$this->config->get('cert.last_count'),
            'last_error' => (string)$this->config->get('cert.last_error'),
        ];
    }

    public function countDomains()
    {
        try {
            return (int)$this->conn()->fetchOne('SELECT COUNT(*) FROM antispam_cert_domain');
        } catch (\Throwable $e) {
            return 0; // table not created yet
        }
    }

    // --- pure helpers (mirrored by the standalone agent) --------------------

    /**
     * Lower-cased ASCII domain, or '' when the line is not a usable domain
     * (comment, IP, single label, invalid characters).
     */
    public static function normalizeDomain($line)
    {
        $d = trim((string)$line);
        if ($d === '' || $d[0] === '#') {
            return '';
        }
        $d = preg_replace('~^\*\.~', '', mb_strtolower($d, 'UTF-8'));
        $d = DomainHelper::toAscii(rtrim($d, '.'));
        if ($d === '' || strlen($d) > 253 || strpos($d, '.') === false || DomainHelper::isIp($d)) {
            return '';
        }
        if (!preg_match('/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/', $d)) {
            return '';
        }
        return $d;
    }

    /**
     * The host and its parents down to two labels:
     * "a.b.example.com" -> [a.b.example.com, b.example.com, example.com].
     *
     * @return string[]
     */
    public static function candidates($host)
    {
        $host = self::normalizeDomain($host);
        if ($host === '') {
            return [];
        }
        $labels = explode('.', $host);
        $out = [];
        for ($i = 0, $n = count($labels); $i <= $n - 2; $i++) {
            $out[] = implode('.', array_slice($labels, $i));
        }
        return $out;
    }

    /** Parses the downloaded text into unique normalized domains. @return string[] */
    public static function parseList($text)
    {
        $set = [];
        foreach (preg_split('/\R/', (string)$text) as $line) {
            if (($d = self::normalizeDomain($line)) !== '') {
                $set[$d] = true;
            }
        }
        return array_keys($set);
    }

    /** Whether a freshly downloaded list may replace the current one. Returns an error text or null. */
    public static function sanityError($newCount, $currentCount)
    {
        if ($newCount < self::MIN_ROWS) {
            return sprintf('pobrana lista jest pusta lub podejrzanie krótka (%d domen) - zachowano poprzednią', $newCount);
        }
        if ($currentCount > 0 && $newCount < $currentCount * self::MIN_RATIO) {
            return sprintf('pobrana lista (%d domen) jest ponad dwukrotnie mniejsza niż obecna (%d) - zachowano poprzednią', $newCount, $currentCount);
        }
        return null;
    }

    /** Sender domains from a "Name <a@b>, c@d" style header value. @return string[] */
    public static function hostsFromAddressHeader($value)
    {
        $hosts = [];
        if (preg_match_all('/@([a-z0-9.\-]+\.[a-z]{2,})/i', (string)$value, $m)) {
            foreach ($m[1] as $h) {
                $hosts[] = DomainHelper::normalize($h);
            }
        }
        return $hosts;
    }

    /** Hosts of the links in a message body. @return string[] */
    public static function linkHosts($html, $text)
    {
        $hosts = [];
        foreach (UrlAnalyzer::extractLinks($html, $text) as $link) {
            if (($h = UrlAnalyzer::hostOf($link['href'])) !== '' && !DomainHelper::isIp($h)) {
                $hosts[$h] = true;
            }
        }
        return array_keys($hosts);
    }

    // --- matching -----------------------------------------------------------

    /**
     * @param string[] $senderHosts domains of From / Reply-To / Return-Path
     * @param string[] $linkHosts   hosts of links found in the body
     *
     * @return array{score:int, reasons:array}
     */
    public function analyze(array $senderHosts, array $linkHosts, $spamThreshold = 10)
    {
        $byCandidate = []; // candidate domain => true, in input order (senders first)
        $hosts = array_merge($senderHosts, array_slice(array_values(array_unique($linkHosts)), 0, self::MAX_LINK_HOSTS));
        foreach ($hosts as $host) {
            foreach (self::candidates($host) as $c) {
                $byCandidate[$c] = true;
            }
        }
        if ($byCandidate) {
            $listed = $this->findListed(array_keys($byCandidate));
            foreach ($byCandidate as $candidate => $_) {
                if (isset($listed[$candidate])) {
                    $score = $this->getScore($spamThreshold);
                    return ['score' => $score, 'reasons' => [['rule' => 'cert_hole:' . $candidate, 'score' => $score]]];
                }
            }
        }
        return ['score' => 0, 'reasons' => []];
    }

    /** Domains out of $domains that are on the list. @return array<string,true> */
    public function findListed(array $domains)
    {
        $found = [];
        // The column is ASCII: a non-ASCII parameter would make MySQL fail the
        // whole IN() with "Illegal mix of collations" (and none can be listed).
        $domains = array_filter(array_map('strval', $domains), fn($d) => $d !== '' && preg_match('/^[\x21-\x7e]+$/', $d) === 1);
        try {
            foreach (array_chunk(array_values(array_unique($domains)), 500) as $chunk) {
                $rows = $this->conn()->fetchFirstColumn(
                    'SELECT domain FROM antispam_cert_domain WHERE domain IN (?)',
                    [$chunk],
                    [ArrayParameterType::STRING]
                );
                foreach ($rows as $r) {
                    $found[strtolower($r)] = true;
                }
            }
        } catch (\Throwable $e) {
            return []; // table missing / DB hiccup = no opinion
        }
        return $found;
    }

    // --- sync ---------------------------------------------------------------

    /**
     * Downloads the list and replaces the table in one transaction.
     *
     * @return array{ok:bool, count:int, message:string}
     */
    public function sync()
    {
        $this->config->set('cert.last_attempt_at', date(DATE_ATOM));
        try {
            $domains = self::parseList($this->download($this->getUrl()));
            if (($err = self::sanityError(count($domains), $this->countDomains())) !== null) {
                throw new \RuntimeException($err);
            }
            $this->replaceAll($domains);
        } catch (\Throwable $e) {
            $this->recordError($e->getMessage());
            return ['ok' => false, 'count' => $this->countDomains(), 'message' => $e->getMessage()];
        }
        $this->config->set('cert.last_sync_at', date(DATE_ATOM));
        $this->config->set('cert.last_count', count($domains));
        $this->config->set('cert.last_error', '');

        return ['ok' => true, 'count' => count($domains), 'message' => sprintf('Zaimportowano %d domen', count($domains))];
    }

    /**
     * Store the failure for the panel. Never throws: a failure to record the
     * error must not hide the error itself (the caller still reports it).
     */
    private function recordError($message)
    {
        $text = date('Y-m-d H:i') . ' - ' . mb_substr(trim((string)$message), 0, self::MAX_ERROR_CHARS, 'UTF-8');
        try {
            $this->config->set('cert.last_error', $text);
        } catch (\Throwable $e) {
            // DB unavailable: the command output / cron log still carries the message.
        }
    }

    /** @param string[] $domains unique, normalized */
    private function replaceAll(array $domains)
    {
        $conn = $this->conn();
        $conn->beginTransaction();
        try {
            $conn->executeStatement('DELETE FROM antispam_cert_domain');
            foreach (array_chunk($domains, self::INSERT_BATCH) as $chunk) {
                $conn->executeStatement(
                    'INSERT INTO antispam_cert_domain (domain) VALUES ' . implode(',', array_fill(0, count($chunk), '(?)')),
                    $chunk
                );
            }
            $conn->commit();
        } catch (\Throwable $e) {
            $conn->rollBack();
            throw $e;
        }
    }

    private function download($url)
    {
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('brak rozszerzenia curl');
        }
        $body = '';
        $tooBig = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_ENCODING => '',
            CURLOPT_USERAGENT => 'pancernapanda-antispam/1.0',
            CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, &$tooBig) {
                $body .= $chunk;
                if (strlen($body) > self::MAX_BYTES) {
                    $tooBig = true;
                    return 0; // abort the transfer
                }
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);

        if ($tooBig) {
            throw new \RuntimeException('odpowiedź przekracza limit ' . (self::MAX_BYTES / 1048576) . ' MB');
        }
        if ($ok === false) {
            throw new \RuntimeException('błąd pobierania: ' . $err);
        }
        if ($status !== 200) {
            throw new \RuntimeException('serwer zwrócił HTTP ' . $status);
        }
        return $body;
    }

    private function conn()
    {
        return $this->em->getConnection();
    }
}
