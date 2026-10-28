<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Learned token counts of the local naive Bayes classifier (docs/bayes.md).
 *
 * `token_hash` is the first 8 bytes of SHA-1 of the token as a signed BIGINT -
 * the words themselves are never stored. `scope` 0 = global, otherwise the
 * Account id (per-mailbox training, bayes.per_mailbox). The row with
 * token_hash = 0 (TOTALS_HASH) of a scope holds the number of learned spam /
 * ham messages in spam_count / ham_count.
 *
 * Written with plain DBAL upserts by Services\Bayes\BayesStore; the entity
 * exists for the schema (migrations, tests).
 */
#[ORM\Entity]
#[ORM\Table(name: 'antispam_bayes_token')]
#[ORM\UniqueConstraint(name: 'uniq_bayes_scope_token', columns: ['scope', 'token_hash'])]
#[ORM\Index(name: 'idx_bayes_token_updated', columns: ['updated_at'])]
class BayesToken
{
    public const TABLE = 'antispam_bayes_token';
    public const TOTALS_HASH = 0;
    public const GLOBAL_SCOPE = 0;

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    #[ORM\Column(name: 'scope', type: 'integer', options: ['default' => 0])]
    private int $scope = self::GLOBAL_SCOPE;

    #[ORM\Column(name: 'token_hash', type: 'bigint')]
    private int|string $tokenHash = 0;

    #[ORM\Column(name: 'spam_count', type: 'integer', options: ['default' => 0])]
    private int $spamCount = 0;

    #[ORM\Column(name: 'ham_count', type: 'integer', options: ['default' => 0])]
    private int $hamCount = 0;

    #[ORM\Column(name: 'updated_at', type: 'datetime')]
    private \DateTimeInterface $updatedAt;

    public function __construct()
    {
        $this->updatedAt = new \DateTime();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getScope(): int
    {
        return $this->scope;
    }

    public function getTokenHash(): int
    {
        return (int)$this->tokenHash;
    }

    public function getSpamCount(): int
    {
        return $this->spamCount;
    }

    public function getHamCount(): int
    {
        return $this->hamCount;
    }
}
