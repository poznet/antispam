<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\AuditLogRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * One entry of the audit log ("Dziennik audytu"): who did what, when and from
 * where in the panel, the end-user area, the digest links, the plugin API and
 * a few console commands. Written by Services\AuditLogger (plain DBAL insert),
 * shown on /audit (ROLE_ADMIN), purged by `antispam:purge` after
 * `audit.retention_days`. See docs/audit.md.
 */
#[ORM\Entity(repositoryClass: AuditLogRepository::class)]
#[ORM\Table(name: 'antispam_audit_log')]
#[ORM\Index(name: 'idx_audit_created_at', columns: ['created_at'])]
#[ORM\Index(name: 'idx_audit_action', columns: ['action'])]
#[ORM\Index(name: 'idx_audit_actor', columns: ['actor'])]
#[ORM\Index(name: 'idx_audit_mailbox', columns: ['mailbox'])]
class AuditLog
{
    const TABLE = 'antispam_audit_log';

    /** Actor types */
    const ACTOR_USER = 'user';
    const ACTOR_ENV_ADMIN = 'env_admin';
    const ACTOR_ANONYMOUS = 'anonymous';
    const ACTOR_DIGEST_LINK = 'digest_link';
    const ACTOR_PLUGIN = 'plugin';
    const ACTOR_CLI = 'cli';

    const ACTOR_TYPES = [
        self::ACTOR_USER => 'użytkownik',
        self::ACTOR_ENV_ADMIN => 'administrator (env)',
        self::ACTOR_ANONYMOUS => 'anonim',
        self::ACTOR_DIGEST_LINK => 'link z raportu',
        self::ACTOR_PLUGIN => 'wtyczka',
        self::ACTOR_CLI => 'konsola',
    ];

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'created_at', type: 'datetime')]
    private $createdAt;

    #[ORM\Column(name: 'actor', type: 'string', length: 180)]
    private $actor;

    #[ORM\Column(name: 'actor_type', type: 'string', length: 20)]
    private $actorType;

    #[ORM\Column(name: 'role', type: 'string', length: 20, nullable: true)]
    private $role;

    #[ORM\Column(name: 'ip', type: 'string', length: 45, nullable: true)]
    private $ip;

    #[ORM\Column(name: 'action', type: 'string', length: 64)]
    private $action;

    #[ORM\Column(name: 'target_type', type: 'string', length: 32, nullable: true)]
    private $targetType;

    #[ORM\Column(name: 'target_id', type: 'string', length: 64, nullable: true)]
    private $targetId;

    #[ORM\Column(name: 'target_label', type: 'string', length: 255, nullable: true)]
    private $targetLabel;

    #[ORM\Column(name: 'mailbox', type: 'string', length: 255, nullable: true)]
    private $mailbox;

    /** Short JSON object, never secrets (AuditLogger::sanitize()). */
    #[ORM\Column(name: 'details', type: 'text', nullable: true)]
    private $details;

    public function getId() { return $this->id; }
    public function getCreatedAt() { return $this->createdAt; }
    public function getActor() { return $this->actor; }
    public function getActorType() { return $this->actorType; }
    public function getActorTypeLabel() { return self::ACTOR_TYPES[$this->actorType] ?? $this->actorType; }
    public function getRole() { return $this->role; }
    public function getIp() { return $this->ip; }
    public function getAction() { return $this->action; }
    public function getTargetType() { return $this->targetType; }
    public function getTargetId() { return $this->targetId; }
    public function getTargetLabel() { return $this->targetLabel; }
    public function getMailbox() { return $this->mailbox; }
    public function getDetails() { return $this->details; }

    /** @return array<string, mixed> */
    public function getDetailsArray(): array
    {
        $d = $this->details ? json_decode($this->details, true) : null;
        return is_array($d) ? $d : [];
    }
}
