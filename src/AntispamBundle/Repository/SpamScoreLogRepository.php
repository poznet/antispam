<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\SpamScoreLog;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Tools\Pagination\Paginator;

class SpamScoreLogRepository extends EntityRepository
{
    public function findRecent($limit = 50, $accountEmail = null)
    {
        $qb = $this->createQueryBuilder('l')
            ->orderBy('l.scoredAt', \SortDirection::Descending)
            ->setMaxResults($limit);
        if ($accountEmail) {
            $qb->andWhere('l.accountEmail = :e')->setParameter('e', $accountEmail);
        }
        return $qb->getQuery()->getResult();
    }

    /**
     * Filtered, paginated score log for the "Dziennik ocen" view.
     *
     * Supported filters (all optional): decision (ham|quarantine|spam|whitelisted),
     * account (exact account e-mail), accounts (list of account e-mails the result is restricted to), q (substring of sender or subject),
     * from / to (\DateTimeInterface, inclusive day range), minScore (int).
     *
     * @return array{items: SpamScoreLog[], total: int}
     */
    public function search(array $filters, int $page = 1, int $perPage = 50): array
    {
        $qb = $this->createQueryBuilder('l')
            ->orderBy('l.scoredAt', \SortDirection::Descending)
            ->addOrderBy('l.id', \SortDirection::Descending);

        if (!empty($filters['decision'])) {
            $qb->andWhere('l.decision = :decision')->setParameter('decision', $filters['decision']);
        }
        if (!empty($filters['account'])) {
            $qb->andWhere('l.accountEmail = :account')->setParameter('account', $filters['account']);
        }
        if (isset($filters['accounts'])) {
            // Ownership scope of a non-admin user: only these account e-mails (an empty list matches nothing).
            if ($filters['accounts'] === []) {
                $qb->andWhere('1 = 0');
            } else {
                $qb->andWhere('l.accountEmail IN (:accounts)')->setParameter('accounts', array_values($filters['accounts']));
            }
        }
        if (isset($filters['q']) && $filters['q'] !== '') {
            // Escape LIKE wildcards so "100%" or "a_b" match literally (portable ESCAPE char, not backslash).
            $like = '%' . strtr($filters['q'], ['!' => '!!', '%' => '!%', '_' => '!_']) . '%';
            $qb->andWhere("(l.sender LIKE :q ESCAPE '!' OR l.subject LIKE :q ESCAPE '!')")->setParameter('q', $like);
        }
        if (!empty($filters['from'])) {
            $from = \DateTime::createFromInterface($filters['from'])->setTime(0, 0, 0);
            $qb->andWhere('l.scoredAt >= :from')->setParameter('from', $from);
        }
        if (!empty($filters['to'])) {
            $to = \DateTime::createFromInterface($filters['to'])->setTime(23, 59, 59);
            $qb->andWhere('l.scoredAt <= :to')->setParameter('to', $to);
        }
        if (isset($filters['minScore'])) {
            $qb->andWhere('l.score >= :minScore')->setParameter('minScore', (int)$filters['minScore']);
        }

        $page = max(1, $page);
        $qb->setFirstResult(($page - 1) * $perPage)->setMaxResults($perPage);
        $paginator = new Paginator($qb->getQuery(), false);

        return ['items' => iterator_to_array($paginator), 'total' => count($paginator)];
    }

    /** Distinct account e-mails present in the log (for the filter dropdown). */
    public function distinctAccounts(): array
    {
        $rows = $this->createQueryBuilder('l')
            ->select('DISTINCT l.accountEmail AS email')
            ->andWhere('l.accountEmail IS NOT NULL')
            ->orderBy('email', \SortDirection::Ascending)
            ->getQuery()
            ->getArrayResult();
        return array_column($rows, 'email');
    }

    public function findRecentByDecision($decision, ?\DateTime $since = null, $limit = 50)
    {
        $qb = $this->createQueryBuilder('l')
            ->andWhere('l.decision = :d')
            ->setParameter('d', $decision)
            ->orderBy('l.scoredAt', \SortDirection::Descending)
            ->setMaxResults($limit);
        if ($since) {
            $qb->andWhere('l.scoredAt >= :since')->setParameter('since', $since);
        }
        return $qb->getQuery()->getResult();
    }

    /** @param string[]|null $accountEmails limit to these mailboxes (null = all, [] = none) */
    public function statsByDecision(?\DateTime $since = null, ?array $accountEmails = null)
    {
        $out = ['ham' => 0, 'quarantine' => 0, 'spam' => 0, 'whitelisted' => 0];
        if ($accountEmails === []) {
            return $out;
        }
        $qb = $this->createQueryBuilder('l')
            ->select('l.decision AS decision, COUNT(l.id) AS cnt')
            ->andWhere('l.initialScan = false')
            ->groupBy('l.decision');
        if ($since) {
            $qb->andWhere('l.scoredAt >= :since')->setParameter('since', $since);
        }
        if ($accountEmails !== null) {
            $qb->andWhere('l.accountEmail IN (:emails)')->setParameter('emails', $accountEmails);
        }
        foreach ($qb->getQuery()->getArrayResult() as $row) {
            $out[$row['decision']] = (int)$row['cnt'];
        }
        return $out;
    }

    public function dailyCounts($days = 14)
    {
        $since = new \DateTime('-' . (int)$days . ' days');
        $since->setTime(0, 0, 0);
        $rows = $this->createQueryBuilder('l')
            ->select("SUBSTRING(l.scoredAt, 1, 10) AS day, l.decision AS decision, COUNT(l.id) AS cnt")
            ->andWhere('l.scoredAt >= :since')
            ->andWhere('l.initialScan = false')
            ->setParameter('since', $since)
            ->groupBy('day, decision')
            ->orderBy('day', \SortDirection::Ascending)
            ->getQuery()
            ->getArrayResult();
        return $rows;
    }
}
