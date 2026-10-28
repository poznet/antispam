<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Messages the Bayes classifier has learned, per scope: a fingerprint
 * (SHA-1 of the Message-ID, or of the token hashes when there is none) and
 * the verdict. Used to skip a message learned twice and to unlearn it when
 * the verdict is reversed (spam report, then "not spam"). No content is kept.
 * Rows older than bayes.message_retention_days are purged (antispam:purge);
 * the token counts stay.
 */
#[ORM\Entity]
#[ORM\Table(name: 'antispam_bayes_message')]
#[ORM\UniqueConstraint(name: 'uniq_bayes_scope_fingerprint', columns: ['scope', 'fingerprint'])]
#[ORM\Index(name: 'idx_bayes_message_learned', columns: ['learned_at'])]
class BayesMessage
{
    public const TABLE = 'antispam_bayes_message';
    public const SPAM = 'spam';
    public const HAM = 'ham';

    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    #[ORM\Column(name: 'scope', type: 'integer', options: ['default' => 0])]
    private int $scope = 0;

    #[ORM\Column(name: 'fingerprint', type: 'string', length: 40)]
    private string $fingerprint = '';

    #[ORM\Column(name: 'verdict', type: 'string', length: 4)]
    private string $verdict = self::SPAM;

    /** Where the verdict came from (plugin, phishing, quarantine, spam_release, command). */
    #[ORM\Column(name: 'source', type: 'string', length: 24, nullable: true)]
    private ?string $source = null;

    #[ORM\Column(name: 'learned_at', type: 'datetime')]
    private \DateTimeInterface $learnedAt;

    public function __construct()
    {
        $this->learnedAt = new \DateTime();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getScope(): int
    {
        return $this->scope;
    }

    public function getFingerprint(): string
    {
        return $this->fingerprint;
    }

    public function getVerdict(): string
    {
        return $this->verdict;
    }

    public function getSource(): ?string
    {
        return $this->source;
    }
}
