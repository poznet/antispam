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
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE')]
    private $user;

    #[ORM\Column(name: 'public_id', type: 'string', length: 16)]
    private $publicId;

    #[ORM\Column(name: 'name', type: 'string', length: 100)]
    private $name;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    #[ORM\Column(name: 'last_used_at', type: 'datetime', nullable: true)]
    private $lastUsedAt;

    public function __construct(User $user, string $publicId, string $name)
    {
        $this->user = $user;
        $this->publicId = $publicId;
        $this->name = $name;
        $this->createdAt = new \DateTime();
    }

    public function getId() { return $this->id; }
    public function getUser(): User { return $this->user; }
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
