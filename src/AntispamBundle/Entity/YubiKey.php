<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\YubiKeyRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * A YubiKey (Yubico OTP) registered by a panel user - see
 * Security\YubiKey\YubiKeyService and docs/users.md#yubikey.
 *
 * Only the public ID is stored: the first 12 (up to 16) modhex characters of
 * every OTP the key types, identical for all its OTPs. It identifies the key,
 * it is not a secret - the OTP itself is checked by the Yubico validation
 * server (YubiCloud or a self-hosted yubikey-val).
 *
 * Owner: a database user (user_id) or the built-in environment administrator
 * (ADMIN_USER, not in the database) - then user_id is NULL and admin_login
 * holds its login; such a key belongs to whoever ADMIN_USER is set to.
 */
#[ORM\Entity(repositoryClass: YubiKeyRepository::class)]
#[ORM\Table(name: 'antispam_yubikey')]
#[ORM\UniqueConstraint(name: 'uniq_antispam_yubikey_public_id', columns: ['public_id'])]
class YubiKey
{
    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: true, onDelete: 'CASCADE')]
    private $user;

    /** Login of the environment admin owning the key (user_id is NULL then). */
    #[ORM\Column(name: 'admin_login', type: 'string', length: 180, nullable: true)]
    private $adminLogin;

    #[ORM\Column(name: 'public_id', type: 'string', length: 16)]
    private $publicId;

    #[ORM\Column(name: 'name', type: 'string', length: 100)]
    private $name;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    #[ORM\Column(name: 'last_used_at', type: 'datetime', nullable: true)]
    private $lastUsedAt;

    public function __construct(?User $user, string $publicId, string $name, ?string $adminLogin = null)
    {
        if (($user === null) === ($adminLogin === null)) {
            throw new \InvalidArgumentException('A YubiKey belongs to a database user or to the environment admin.');
        }
        $this->user = $user;
        $this->adminLogin = $adminLogin;
        $this->publicId = $publicId;
        $this->name = $name;
        $this->createdAt = new \DateTime();
    }

    public function getId() { return $this->id; }
    public function getUser(): ?User { return $this->user; }
    public function getAdminLogin(): ?string { return $this->adminLogin; }
    /** Login of the owner (database user or env admin). */
    public function getOwnerLogin(): string { return $this->user ? $this->user->getUserIdentifier() : (string)$this->adminLogin; }
    public function getPublicId(): string { return (string)$this->publicId; }
    public function getName(): string { return (string)$this->name; }
    public function getCreatedAt(): \DateTimeInterface { return $this->createdAt; }
    public function getLastUsedAt(): ?\DateTimeInterface { return $this->lastUsedAt; }

    public function markUsed(): self
    {
        $this->lastUsedAt = new \DateTime();
        return $this;
    }
}
