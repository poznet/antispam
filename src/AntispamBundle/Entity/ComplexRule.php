<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\ComplexRuleRepository;
use AntispamBundle\Services\ComplexRuleEngine;
use Doctrine\ORM\Mapping as ORM;

/**
 * Complex rule ("Reguła złożona"): a tree of conditions joined with AND / OR
 * (ComplexRuleEngine) and an action. Owned like the white / blacklists: a
 * mailbox address or RuleOwnership::ALL ('*') for every mailbox.
 */
#[ORM\Entity(repositoryClass: ComplexRuleRepository::class)]
#[ORM\Table(name: 'antispam_complex_rule')]
#[ORM\Index(name: 'idx_complex_rule_email', columns: ['email'])]
class ComplexRule
{
    public const ACTION_SPAM = 'spam';
    public const ACTION_QUARANTINE = 'quarantine';
    public const ACTION_SCORE = 'score';
    public const ACTION_WHITELIST = 'whitelist';
    /** Test mode: a match is only written to the score log (0 points). */
    public const ACTION_LOG = 'log';

    public const SOURCE_PANEL = 'panel';
    public const SOURCE_PLUGIN = 'plugin';
    public const SOURCE_USER = 'user';
    public const SOURCE_IMPORT = 'import';

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    /** Owner mailbox address, or RuleOwnership::ALL ('*'). */
    #[ORM\Column(name: 'email', type: 'string', length: 255)]
    private string $email = '';

    #[ORM\Column(name: 'name', type: 'string', length: 120)]
    private string $name = '';

    #[ORM\Column(name: 'enabled', type: 'boolean')]
    private bool $enabled = true;

    #[ORM\Column(name: 'action', type: 'string', length: 16)]
    private string $action = self::ACTION_SPAM;

    #[ORM\Column(name: 'score', type: 'integer')]
    private int $score = 10;

    /** Condition tree, JSON (ComplexRuleEngine::normalize()). */
    #[ORM\Column(name: 'conditions', type: 'text')]
    private string $conditions = '{"op":"and","items":[]}';

    #[ORM\Column(name: 'counter', type: 'integer')]
    private int $counter = 0;

    #[ORM\Column(name: 'source', type: 'string', length: 16)]
    private string $source = self::SOURCE_PANEL;

    /** Who created it: "admin:<login>", "plugin:<mailbox>", "user:<login>". */
    #[ORM\Column(name: 'created_by', type: 'string', length: 255, nullable: true)]
    private ?string $createdBy = null;

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(name: 'updated_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $updatedAt;

    public function __construct()
    {
        $this->createdAt = new \DateTimeImmutable();
        $this->updatedAt = $this->createdAt;
    }

    public function getId(): ?int { return $this->id; }

    public function getEmail(): string { return $this->email; }
    public function setEmail(string $email): self { $this->email = $email; return $this; }

    public function getName(): string { return $this->name; }
    public function setName(string $name): self { $this->name = mb_substr(trim($name), 0, ComplexRuleEngine::MAX_NAME); return $this; }

    public function isEnabled(): bool { return $this->enabled; }
    public function setEnabled(bool $enabled): self { $this->enabled = $enabled; return $this; }

    public function getAction(): string { return $this->action; }
    public function setAction(string $action): self { $this->action = $action; return $this; }

    public function getScore(): int { return $this->score; }
    public function setScore(int $score): self { $this->score = $score; return $this; }

    public function getConditions(): string { return $this->conditions; }

    public function getConditionTree(): array
    {
        $tree = json_decode($this->conditions, true);
        return is_array($tree) ? $tree : ['op' => 'and', 'items' => []];
    }

    public function setConditionTree(array $tree): self
    {
        $this->conditions = json_encode($tree, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        return $this;
    }

    public function getCounter(): int { return $this->counter; }
    public function setCounter(int $counter): self { $this->counter = $counter; return $this; }

    public function getSource(): string { return $this->source; }
    public function setSource(string $source): self { $this->source = $source; return $this; }

    public function getCreatedBy(): ?string { return $this->createdBy; }
    public function setCreatedBy(?string $createdBy): self { $this->createdBy = $createdBy === null ? null : mb_substr($createdBy, 0, 255); return $this; }

    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
    public function setCreatedAt(\DateTimeImmutable $at): self { $this->createdAt = $at; return $this; }

    public function getUpdatedAt(): \DateTimeImmutable { return $this->updatedAt; }
    public function touch(): self { $this->updatedAt = new \DateTimeImmutable(); return $this; }

    public function describe(): string
    {
        return ComplexRuleEngine::describe($this->getConditionTree());
    }

    public function getActionLabel(): string
    {
        return ComplexRuleEngine::ACTIONS[$this->action] ?? $this->action;
    }

    /** Reason entry of the score log. */
    public function reasonRule(): string
    {
        return 'complex_rule:#' . $this->id . ' ' . $this->name . ' (' . $this->action . ')';
    }
}
