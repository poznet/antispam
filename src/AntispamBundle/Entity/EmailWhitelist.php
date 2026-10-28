<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\EmailWhitelistRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: EmailWhitelistRepository::class)]
#[ORM\Table(name: 'antispam_email_whitelist')]
class EmailWhitelist
{
    const PATTERN_EXACT = 'exact';
    const PATTERN_WILDCARD = 'wildcard';
    const PATTERN_REGEX = 'regex';

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    /** Owner mailbox address, or RuleOwnership::ALL ('*') for a rule applied to every mailbox. */
    #[ORM\Column(name: 'email', type: 'string', length: 255)]
    private $email;

    #[ORM\Column(name: 'whitelistemail', type: 'string', length: 255)]
    private $whitelistemail;

    #[ORM\Column(name: 'pattern_type', type: 'string', length: 16)]
    private $patternType = self::PATTERN_EXACT;

    #[ORM\Column(name: 'counter', type: 'integer')]
    private $counter = 0;

    public function getId() { return $this->id; }

    public function setEmail($email) { $this->email = $email; return $this; }
    public function getEmail() { return $this->email; }

    public function setWhitelistemail($whitelistemail) { $this->whitelistemail = $whitelistemail; return $this; }
    public function getWhitelistemail() { return $this->whitelistemail; }

    public function getPatternType() { return $this->patternType; }
    public function setPatternType($patternType) { $this->patternType = $patternType; return $this; }

    public function setCounter($counter) { $this->counter = $counter; return $this; }
    public function getCounter() { return $this->counter; }
}
