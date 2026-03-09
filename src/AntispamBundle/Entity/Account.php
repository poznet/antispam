<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Table(name="antispam_account")
 * @ORM\Entity(repositoryClass="AntispamBundle\Repository\AccountRepository")
 */
class Account
{
    const CONNECTION_IMAP = 'imap';
    const CONNECTION_SSH = 'ssh';

    /**
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @ORM\Column(name="name", type="string", length=255)
     */
    private $name;

    /**
     * @ORM\Column(name="email", type="string", length=255)
     */
    private $email;

    /**
     * @ORM\Column(name="connection_type", type="string", length=10)
     */
    private $connectionType = self::CONNECTION_IMAP;

    // IMAP fields

    /**
     * @ORM\Column(name="imap_host", type="string", length=255, nullable=true)
     */
    private $imapHost;

    /**
     * @ORM\Column(name="imap_port", type="integer", nullable=true)
     */
    private $imapPort = 143;

    /**
     * @ORM\Column(name="imap_login", type="string", length=255, nullable=true)
     */
    private $imapLogin;

    /**
     * @ORM\Column(name="imap_password", type="string", length=255, nullable=true)
     */
    private $imapPassword;

    /**
     * @ORM\Column(name="imap_flags", type="string", length=255, nullable=true)
     */
    private $imapFlags = '/novalidate-cert/notls';

    // SSH fields

    /**
     * @ORM\Column(name="ssh_host", type="string", length=255, nullable=true)
     */
    private $sshHost;

    /**
     * @ORM\Column(name="ssh_port", type="integer", nullable=true)
     */
    private $sshPort = 22;

    /**
     * @ORM\Column(name="ssh_user", type="string", length=255, nullable=true)
     */
    private $sshUser;

    /**
     * @ORM\Column(name="ssh_key_path", type="string", length=500, nullable=true)
     */
    private $sshKeyPath;

    /**
     * @ORM\Column(name="maildir_path", type="string", length=500, nullable=true)
     */
    private $maildirPath = '~/Maildir';

    /**
     * @ORM\Column(name="agent_path", type="string", length=500, nullable=true)
     */
    private $agentPath = '~/antispam-agent';

    // Common fields

    /**
     * @ORM\Column(name="delete_spam", type="boolean")
     */
    private $deleteSpam = false;

    /**
     * @ORM\Column(name="agent_deployed", type="boolean")
     */
    private $agentDeployed = false;

    /**
     * @ORM\Column(name="last_scan_at", type="datetime", nullable=true)
     */
    private $lastScanAt;

    /**
     * @ORM\Column(name="last_scan_result", type="text", nullable=true)
     */
    private $lastScanResult;

    public function getId() { return $this->id; }

    public function getName() { return $this->name; }
    public function setName($name) { $this->name = $name; return $this; }

    public function getEmail() { return $this->email; }
    public function setEmail($email) { $this->email = $email; return $this; }

    public function getConnectionType() { return $this->connectionType; }
    public function setConnectionType($connectionType) { $this->connectionType = $connectionType; return $this; }

    public function isImap() { return $this->connectionType === self::CONNECTION_IMAP; }
    public function isSsh() { return $this->connectionType === self::CONNECTION_SSH; }

    public function getImapHost() { return $this->imapHost; }
    public function setImapHost($imapHost) { $this->imapHost = $imapHost; return $this; }

    public function getImapPort() { return $this->imapPort; }
    public function setImapPort($imapPort) { $this->imapPort = $imapPort; return $this; }

    public function getImapLogin() { return $this->imapLogin; }
    public function setImapLogin($imapLogin) { $this->imapLogin = $imapLogin; return $this; }

    public function getImapPassword() { return $this->imapPassword; }
    public function setImapPassword($imapPassword) { $this->imapPassword = $imapPassword; return $this; }

    public function getImapFlags() { return $this->imapFlags; }
    public function setImapFlags($imapFlags) { $this->imapFlags = $imapFlags; return $this; }

    public function getSshHost() { return $this->sshHost; }
    public function setSshHost($sshHost) { $this->sshHost = $sshHost; return $this; }

    public function getSshPort() { return $this->sshPort; }
    public function setSshPort($sshPort) { $this->sshPort = $sshPort; return $this; }

    public function getSshUser() { return $this->sshUser; }
    public function setSshUser($sshUser) { $this->sshUser = $sshUser; return $this; }

    public function getSshKeyPath() { return $this->sshKeyPath; }
    public function setSshKeyPath($sshKeyPath) { $this->sshKeyPath = $sshKeyPath; return $this; }

    public function getMaildirPath() { return $this->maildirPath; }
    public function setMaildirPath($maildirPath) { $this->maildirPath = $maildirPath; return $this; }

    public function getAgentPath() { return $this->agentPath; }
    public function setAgentPath($agentPath) { $this->agentPath = $agentPath; return $this; }

    public function getDeleteSpam() { return $this->deleteSpam; }
    public function setDeleteSpam($deleteSpam) { $this->deleteSpam = $deleteSpam; return $this; }

    public function getAgentDeployed() { return $this->agentDeployed; }
    public function setAgentDeployed($agentDeployed) { $this->agentDeployed = $agentDeployed; return $this; }

    public function getLastScanAt() { return $this->lastScanAt; }
    public function setLastScanAt($lastScanAt) { $this->lastScanAt = $lastScanAt; return $this; }

    public function getLastScanResult() { return $this->lastScanResult; }
    public function setLastScanResult($lastScanResult) { $this->lastScanResult = $lastScanResult; return $this; }

    public function getLastScanResultDecoded()
    {
        return $this->lastScanResult ? json_decode($this->lastScanResult, true) : null;
    }
}
