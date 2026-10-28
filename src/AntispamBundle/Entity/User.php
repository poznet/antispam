<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Panel user. ROLE_ADMIN sees everything; ROLE_USER only the quarantine, spam
 * and score log of the mailboxes (Account) assigned to it.
 *
 * The legacy single administrator from ADMIN_USER / ADMIN_PASSWORD_HASH is not
 * stored here (see AdminUserProvider).
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'antispam_user')]
#[ORM\UniqueConstraint(name: 'uniq_antispam_user_username', columns: ['username'])]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    const ROLE_ADMIN = 'ROLE_ADMIN';
    const ROLE_USER = 'ROLE_USER';
    const ROLES = [self::ROLE_USER, self::ROLE_ADMIN];

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'username', type: 'string', length: 180)]
    private $username;

    #[ORM\Column(name: 'password', type: 'string', length: 255)]
    private $password;

    #[ORM\Column(name: 'role', type: 'string', length: 20)]
    private $role = self::ROLE_USER;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    /**
     * Two-factor authentication (TOTP, see Security\TwoFactor\TwoFactorService).
     * The base32 secret is stored encrypted (CryptoService, "enc:v1:"); 2FA is
     * on only when both the secret and totp_enabled_at are set.
     */
    #[ORM\Column(name: 'totp_secret', type: 'string', length: 255, nullable: true)]
    private $totpSecret;

    #[ORM\Column(name: 'totp_enabled_at', type: 'datetime', nullable: true)]
    private $totpEnabledAt;

    /** Last accepted TOTP time step - a code is accepted only once (replay protection). */
    #[ORM\Column(name: 'totp_last_counter', type: 'integer', nullable: true)]
    private $totpLastCounter;

    /** @var string[]|null password_hash() of the unused backup codes */
    #[ORM\Column(name: 'totp_backup_codes', type: 'json', nullable: true)]
    private $totpBackupCodes;

    /** @var Collection<int, Account> */
    #[ORM\ManyToMany(targetEntity: Account::class)]
    #[ORM\JoinTable(name: 'antispam_user_account')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', onDelete: 'CASCADE')]
    #[ORM\InverseJoinColumn(name: 'account_id', referencedColumnName: 'id', onDelete: 'CASCADE')]
    private $accounts;

    public function __construct()
    {
        $this->accounts = new ArrayCollection();
        $this->createdAt = new \DateTime();
    }

    public function getId() { return $this->id; }

    public function getUsername() { return $this->username; }
    public function setUsername($username) { $this->username = $username; return $this; }

    public function getUserIdentifier(): string
    {
        return (string)$this->username;
    }

    public function getPassword(): ?string { return $this->password; }
    public function setPassword($password) { $this->password = $password; return $this; }

    public function getRole() { return $this->role; }
    public function setRole($role) { $this->role = $role; return $this; }

    public function isAdmin() { return $this->role === self::ROLE_ADMIN; }

    public function getRoles(): array
    {
        return array_values(array_unique([$this->role, self::ROLE_USER]));
    }

    public function getCreatedAt() { return $this->createdAt; }

    public function getTotpSecret(): ?string { return $this->totpSecret; }
    public function setTotpSecret(?string $secret) { $this->totpSecret = $secret; return $this; }

    public function getTotpEnabledAt(): ?\DateTimeInterface { return $this->totpEnabledAt; }
    public function setTotpEnabledAt(?\DateTimeInterface $at) { $this->totpEnabledAt = $at; return $this; }

    public function getTotpLastCounter(): ?int { return $this->totpLastCounter === null ? null : (int)$this->totpLastCounter; }
    public function setTotpLastCounter(?int $counter) { $this->totpLastCounter = $counter; return $this; }

    /** @return string[] hashes of the unused backup codes */
    public function getTotpBackupCodes(): array { return array_values((array)($this->totpBackupCodes ?? [])); }
    /** @param string[]|null $hashes */
    public function setTotpBackupCodes(?array $hashes) { $this->totpBackupCodes = $hashes === null ? null : array_values($hashes); return $this; }

    public function isTotpEnabled(): bool
    {
        return $this->totpSecret !== null && $this->totpSecret !== '' && $this->totpEnabledAt !== null;
    }

    /** Turn 2FA off and forget every secret (disable / admin reset). */
    public function clearTotp()
    {
        $this->totpSecret = null;
        $this->totpEnabledAt = null;
        $this->totpLastCounter = null;
        $this->totpBackupCodes = null;
        return $this;
    }

    /** @return Collection<int, Account> */
    public function getAccounts()
    {
        return $this->accounts ?? ($this->accounts = new ArrayCollection());
    }

    public function addAccount(Account $account)
    {
        if (!$this->getAccounts()->contains($account)) {
            $this->getAccounts()->add($account);
        }
        return $this;
    }

    /** Replace the assigned mailboxes. @param iterable<Account> $accounts */
    public function setAccounts(iterable $accounts)
    {
        $this->getAccounts()->clear();
        foreach ($accounts as $account) {
            $this->addAccount($account);
        }
        return $this;
    }

    public function eraseCredentials(): void
    {
    }

    /**
     * Session payload: no collections, and only a hash of the password hash, so
     * changing the password logs the user out everywhere (Symfony compares the
     * crc32c value against the refreshed user).
     */
    public function __serialize(): array
    {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'password' => hash('crc32c', (string)$this->password),
            'role' => $this->role,
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->id = $data['id'] ?? null;
        $this->username = $data['username'] ?? null;
        $this->password = $data['password'] ?? null;
        $this->role = $data['role'] ?? self::ROLE_USER;
        $this->createdAt = new \DateTime();
        $this->accounts = new ArrayCollection();
    }
}
