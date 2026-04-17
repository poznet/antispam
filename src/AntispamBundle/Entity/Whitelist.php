<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Table(name="antispam_whitelist")
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\WhitelistRepository")
 */
class Whitelist
{
    const PATTERN_EXACT = 'exact';
    const PATTERN_WILDCARD = 'wildcard';
    const PATTERN_REGEX = 'regex';

    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="email", type="string", length=255)
     */
    private $email;

    /**
     * @ORM\Column(name="host", type="string", length=255)
     */
    private $host;

    /**
     * @ORM\Column(name="pattern_type", type="string", length=16)
     */
    private $patternType = self::PATTERN_EXACT;

    /**
     * @ORM\Column(name="counter", type="integer")
     */
    private $counter = 0;

    public function getId() { return $this->id; }

    public function setEmail($email) { $this->email = $email; return $this; }
    public function getEmail() { return $this->email; }

    public function setHost($host) { $this->host = $host; return $this; }
    public function getHost() { return $this->host; }

    public function getPatternType() { return $this->patternType; }
    public function setPatternType($patternType) { $this->patternType = $patternType; return $this; }

    public function setCounter($counter) { $this->counter = $counter; return $this; }
    public function getCounter() { return $this->counter; }
}
