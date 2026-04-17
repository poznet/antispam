<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Cache of DNSBL lookups so we don't hammer DNS on every scan.
 *
 * @ORM\Table(name="antispam_dnsbl_cache", indexes={
 *   @ORM\Index(name="idx_ip_zone", columns={"ip", "zone"})
 * })
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\DnsblCacheRepository")
 */
class DnsblCache
{
    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="ip", type="string", length=45)
     */
    private $ip;

    /**
     * @ORM\Column(name="zone", type="string", length=255)
     */
    private $zone;

    /**
     * @ORM\Column(name="listed", type="boolean")
     */
    private $listed = false;

    /**
     * @ORM\Column(name="response", type="string", length=64, nullable=true)
     */
    private $response;

    /**
     * @ORM\Column(name="checked_at", type="datetime")
     */
    private $checkedAt;

    public function __construct()
    {
        $this->checkedAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getIp() { return $this->ip; }
    public function setIp($ip) { $this->ip = $ip; return $this; }

    public function getZone() { return $this->zone; }
    public function setZone($zone) { $this->zone = $zone; return $this; }

    public function isListed() { return $this->listed; }
    public function getListed() { return $this->listed; }
    public function setListed($listed) { $this->listed = (bool)$listed; return $this; }

    public function getResponse() { return $this->response; }
    public function setResponse($response) { $this->response = $response; return $this; }

    public function getCheckedAt() { return $this->checkedAt; }
    public function setCheckedAt(\DateTime $dt) { $this->checkedAt = $dt; return $this; }

    public function isExpired($ttlSeconds)
    {
        return (time() - $this->checkedAt->getTimestamp()) > $ttlSeconds;
    }
}
