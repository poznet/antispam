<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Queries DNS-based block lists (Spamhaus, SORBS, Barracuda, ...) for a given
 * IPv4 address, caching responses in the database with per-provider TTL.
 */
class DnsblService
{
    private $em;

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
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

        $providers = $this->em->getRepository('AntispamBundle:DnsblProvider')->findEnabled();
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
                $provider->incrementHits();
            }
        }
        $this->em->flush();
        return $score;
    }

    private function isListed($ip, DnsblProvider $provider, &$response = null)
    {
        $response = null;
        $zone = $provider->getZone();

        $cache = $this->em->getRepository('AntispamBundle:DnsblCache')
            ->findFresh($ip, $zone);

        if ($cache && !$cache->isExpired($provider->getCacheTtl())) {
            $response = $cache->getResponse();
            return $cache->isListed();
        }

        $query = $this->reverseIp($ip) . '.' . $zone;
        $listed = false;
        $responseIp = null;

        // gethostbyname returns the input if resolution fails; use checkdnsrr for A lookup.
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($query, DNS_A);
            if (is_array($records) && count($records) > 0) {
                $listed = true;
                $responseIp = $records[0]['ip'] ?? null;
            }
        } else {
            $resolved = @gethostbyname($query);
            if ($resolved && $resolved !== $query && filter_var($resolved, FILTER_VALIDATE_IP)) {
                $listed = true;
                $responseIp = $resolved;
            }
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

        $response = $responseIp;
        return $listed;
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
