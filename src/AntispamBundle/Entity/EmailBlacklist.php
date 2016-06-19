<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Whitelist
 *
 * @ORM\Table(name="antispam_email_blacklist")
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\EmailBlacklistRepository")
 */
class EmailBlacklist
{
    /**
     * @var int
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var string
     *
     * @ORM\Column(name="email", type="string", length=255)
     */
    private $email;

    /**
     * @var string
     *
     * @ORM\Column(name="blacklistemail", type="string", length=255)
     */
    private $blacklistemail;

    /**
     * @var integer
     *
     * @ORM\Column(name="counter", type="integer", )
     */
    private $counter=0;

    /**
     * Get id
     *
     * @return integer 
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set email
     *
     * @param string $email
     * @return Whitelist
     */
    public function setEmail($email)
    {
        $this->email = $email;

        return $this;
    }

    /**
     * Get email
     *
     * @return string 
     */
    public function getEmail()
    {
        return $this->email;
    }

 
    /**
     * Set counter
     *
     * @param integer $counter
     * @return Blacklist
     */
    public function setCounter($counter)
    {
        $this->counter = $counter;

        return $this;
    }

    /**
     * Get counter
     *
     * @return integer 
     */
    public function getCounter()
    {
        return $this->counter;
    }

    /**
     * Set blacklistemail
     *
     * @param string $blacklistemail
     * @return EmailBlacklist
     */
    public function setBlacklistemail($blacklistemail)
    {
        $this->blacklistemail = $blacklistemail;

        return $this;
    }

    /**
     * Get blacklistemail
     *
     * @return string 
     */
    public function getBlacklistemail()
    {
        return $this->blacklistemail;
    }
}
