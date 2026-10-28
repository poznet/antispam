<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Queries DNS-based block lists (Spamhaus, SORBS, Barracuda, ...) for a given
 * IPv4 address, caching responses in the database with per-provider TTL.
 *
 * Only an answer in 127.0.0.0/8 counts as a listing - and not 127.0.0.1
 * (URIBL & co. "query refused") nor 127.255.255.0/24 (Spamhaus error codes,
 * e.g. queries through a public resolver). Any other answer (an ISP resolver
 * "helpfully" answering NXDOMAIN with its own IP) and DNS errors are treated
 * as "not listed" and are not cached, so a broken resolver cannot mark every
 * sender as listed for the whole cache TTL.
 *
 * A zone whose lookups keep failing or are slow is skipped for the rest of
 * the process (circuit breaker): PHP's resolver has no per-call timeout, so a
 * dead DNSBL would otherwise cost seconds on every single message.
 */
class DnsblService
{
    /** A lookup slower than this (seconds) counts as a failure for the breaker. */
    const SLOW_LOOKUP_SECONDS = 3.0;
    /** Failed / slow lookups after which a zone is skipped until the process ends. */
    const MAX_FAILURES = 3;

    private $em;
    private $resolver;
    /** @var array<string, int> zone => failed or slow lookups in this process */
    private $failures = [];

    /**
     * @param callable|null $resolver fn(string $fqdn): string[]|null (null = DNS error); tests only
     */
    public function __construct(EntityManagerInterface $em, ?callable $resolver = null)
    {
        $this->em = $em;
        $this->resolver = $resolver;
    }

    /**
     * True when $ip is a DNSBL "listed" return code (see class doc).
     */
    public static function isListingAddress($ip)
    {
        $ip = (string)$ip;
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || strpos($ip, '127.') !== 0) {
            return false;
        }
        return $ip !== '127.0.0.1' && strpos($ip, '127.255.255.') !== 0;
    }

    /**
     * A records of $fqdn: [] when the name does not exist, null on a DNS error.
     *
     * @return string[]|null
     */
    public static function lookupA($fqdn)
    {
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($fqdn, DNS_A);
            if ($records === false) {
                return null;
            }
            return array_values(array_filter(array_column($records, 'ip')));
        }
        $resolved = @gethostbyname($fqdn);
        return ($resolved && $resolved !== $fqdn && filter_var($resolved, FILTER_VALIDATE_IP)) ? [$resolved] : [];
    }

    /**
     * @return array list of ['provider' => DnsblProvider, 'listed' => bool, 'response' => string|null]
     */
    public function checkIp($ip)
    {
        $results = [];
        if (!$this->isValidIpv4($ip)) {
            return $results;
        }

        $providers = $this->em->getRepository(DnsblProvider::class)->findEnabled();
        foreach ($providers as $provider) {
            $results[] = [
                'provider' => $provider,
                'listed' => $this->isListed($ip, $provider, $response),
                'response' => $response,
            ];
        }
        return $results;
    }

    /**
     * Sum of scores for providers that list the given IP.
     */
    public function scoreForIp($ip, array &$reasons = [])
    {
        $score = 0;
        foreach ($this->checkIp($ip) as $r) {
            if ($r['listed']) {
                $provider = $r['provider'];
                $score += $provider->getScore();
                $reasons[] = [
                    'rule' => 'dnsbl:' . $provider->getZone(),
                    'score' => $provider->getScore(),
                    'response' => $r['response'],
                ];
                $this->incrementHits($provider);
            }
        }
        return $score;
    }

    private function isListed($ip, DnsblProvider $provider, &$response = null)
    {
        $response = null;
        $zone = $provider->getZone();

        $cache = $this->em->getRepository(DnsblCache::class)
            ->findFresh($ip, $zone);

        // A "listed" row whose response is not a listing code was written
        // before the response check existed - drop it and ask again.
        if ($cache && $cache->isListed() && !self::isListingAddress($cache->getResponse())) {
            $this->em->remove($cache);
            $this->em->flush();
            $cache = null;
        }
        if ($cache && !$cache->isExpired($provider->getCacheTtl())) {
            $response = $cache->getResponse();
            $listed = $cache->isListed();
            $this->em->detach($cache);
            return $listed;
        }

        if (($this->failures[$zone] ?? 0) >= self::MAX_FAILURES) {
            return false; // zone tripped the breaker: skip, do not cache
        }

        $started = microtime(true);
        $records = $this->resolver
            ? call_user_func($this->resolver, $this->reverseIp($ip) . '.' . $zone)
            : self::lookupA($this->reverseIp($ip) . '.' . $zone);
        if ($records === null || microtime(true) - $started > self::SLOW_LOOKUP_SECONDS) {
            $this->failures[$zone] = ($this->failures[$zone] ?? 0) + 1;
        }
        if ($records === null) {
            return false; // DNS error: not listed, and not cached
        }

        $listed = false;
        $responseIp = null;
        foreach ($records as $record) {
            if (self::isListingAddress($record)) {
                $listed = true;
                $responseIp = $record;
                break;
            }
        }
        if (!$listed && $records) {
            // Error code / refused / hijacked answer: says nothing about the IP.
            $response = (string)$records[0];
            return false;
        }

        if (!$cache) {
            $cache = new DnsblCache();
            $cache->setIp($ip)->setZone($zone);
            $this->em->persist($cache);
        }
        $cache->setListed($listed)
              ->setResponse($responseIp)
              ->setCheckedAt(new \DateTime());
        $this->em->flush();
        // Cache rows are looked up again by query; keep them out of the
        // unit of work so a long scan does not accumulate them.
        $this->em->detach($cache);

        $response = $responseIp;
        return $listed;
    }

    /** hits = hits + 1 in SQL: concurrent scans must not lose hits. */
    private function incrementHits(DnsblProvider $provider)
    {
        if ($provider->getId() === null) {
            return;
        }
        $this->em->createQuery('UPDATE ' . DnsblProvider::class . ' p SET p.hits = p.hits + 1 WHERE p.id = :id')
            ->setParameter('id', $provider->getId())
            ->execute();
    }

    private function reverseIp($ip)
    {
        return implode('.', array_reverse(explode('.', $ip)));
    }

    private function isValidIpv4($ip)
    {
        return (bool)filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }
}
