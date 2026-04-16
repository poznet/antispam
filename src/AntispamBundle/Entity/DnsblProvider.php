<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Configurable DNSBL / DNS block list zone (e.g. zen.spamhaus.org).
 *
 * @ORM\Table(name="antispam_dnsbl_provider")
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\DnsblProviderRepository")
 */
class DnsblProvider
{
    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="name", type="string", length=128)
     */
    private $name;

    /**
     * DNSBL zone to query, e.g. "zen.spamhaus.org".
     *
     * @ORM\Column(name="zone", type="string", length=255, unique=true)
     */
    private $zone;

    /**
     * Points added to spam score when the IP is listed by this provider.
     *
     * @ORM\Column(name="score", type="integer")
     */
    private $score = 5;

    /**
     * @ORM\Column(name="enabled", type="boolean")
     */
    private $enabled = true;

    /**
     * Number of successful hits (IP listed) recorded so far.
     *
     * @ORM\Column(name="hits", type="integer")
     */
    private $hits = 0;

    /**
     * TTL in seconds for cached lookups.
     *
     * @ORM\Column(name="cache_ttl", type="integer")
     */
    private $cacheTtl = 3600;

    public function getId() { return $this->id; }

    public function getName() { return $this->name; }
    public function setName($name) { $this->name = $name; return $this; }

    public function getZone() { return $this->zone; }
    public function setZone($zone) { $this->zone = strtolower(trim($zone)); return $this; }

    public function getScore() { return $this->score; }
    public function setScore($score) { $this->score = (int)$score; return $this; }

    public function isEnabled() { return $this->enabled; }
    public function getEnabled() { return $this->enabled; }
    public function setEnabled($enabled) { $this->enabled = (bool)$enabled; return $this; }

    public function getHits() { return $this->hits; }
    public function setHits($hits) { $this->hits = (int)$hits; return $this; }
    public function incrementHits() { $this->hits++; return $this; }

    public function getCacheTtl() { return $this->cacheTtl; }
    public function setCacheTtl($ttl) { $this->cacheTtl = max(60, (int)$ttl); return $this; }
}
