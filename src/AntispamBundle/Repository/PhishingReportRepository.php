<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\PhishingReport;
use Doctrine\ORM\EntityRepository;

class PhishingReportRepository extends EntityRepository
{
    /** Columns for the list view - everything except the raw source. */
    private const LIST_FIELDS = 'r.id, r.createdAt, r.lastReportedAt, r.reportCount, r.accountEmail, r.reportedFrom, r.reportOnly, r.client, r.sender, r.senderName, r.replyTo, r.subject, r.size, r.truncated, r.status, r.sha256, r.forwardedAt, r.forwardedTo, r.forwardError';

    /**
     * Filters (all optional): status, account, q (sender / reply-to / subject substring).
     *
     * @return array{rows: array<int, array>, total: int}
     */
    public function findList(array $filters, $limit = 50, $offset = 0)
    {
        $qb = $this->createQueryBuilder('r');
        if (!empty($filters['status'])) {
            $qb->andWhere('r.status = :status')->setParameter('status', $filters['status']);
        }
        if (!empty($filters['account'])) {
            $qb->andWhere('r.accountEmail = :account')->setParameter('account', $filters['account']);
        }
        if (isset($filters['q']) && trim($filters['q']) !== '') {
            // Explicit, portable ESCAPE char (backslash is only MySQL's implicit default).
            $qb->andWhere("(r.sender LIKE :q ESCAPE '!' OR r.replyTo LIKE :q ESCAPE '!' OR r.subject LIKE :q ESCAPE '!')")
               ->setParameter('q', '%' . strtr(trim($filters['q']), ['!' => '!!', '%' => '!%', '_' => '!_']) . '%');
        }

        $total = (int)(clone $qb)->select('COUNT(r.id)')->getQuery()->getSingleScalarResult();
        $rows = $qb->select(self::LIST_FIELDS)
            ->orderBy('r.lastReportedAt', 'DESC')
            ->setMaxResults($limit)
            ->setFirstResult($offset)
            ->getQuery()->getArrayResult();

        return ['rows' => $rows, 'total' => $total];
    }

    /** @return array<string, int> status => count */
    public function countByStatus()
    {
        $out = array_fill_keys(array_keys(PhishingReport::STATUSES), 0);
        foreach ($this->createQueryBuilder('r')->select('r.status, COUNT(r.id) AS n')->groupBy('r.status')->getQuery()->getArrayResult() as $row) {
            $out[$row['status']] = (int)$row['n'];
        }
        return $out;
    }

    /** @return string[] */
    public function distinctAccounts()
    {
        return array_column($this->createQueryBuilder('r')->select('DISTINCT r.accountEmail AS a')->orderBy('a')->getQuery()->getArrayResult(), 'a');
    }

    /** Total size of the stored sources of one mailbox, or of all of them. */
    public function storedBytes($accountEmail = null)
    {
        $qb = $this->createQueryBuilder('r')->select('COALESCE(SUM(r.size), 0)');
        if ($accountEmail !== null) {
            $qb->where('r.accountEmail = :a')->setParameter('a', $accountEmail);
        }
        return (int)$qb->getQuery()->getSingleScalarResult();
    }

    /**
     * Atomically mark a report as "being forwarded" so a double click or a
     * parallel cron run cannot send it twice. Fails when it was already
     * forwarded or another attempt started less than $stale ago and has not
     * failed yet. $force skips the "already forwarded" check (confirmed resend).
     */
    public function claimForForward(int $id, \DateTime $now, \DateTime $stale, bool $force = false): bool
    {
        $qb = $this->getEntityManager()->createQueryBuilder()
            ->update(PhishingReport::class, 'r')
            ->set('r.forwardAttemptedAt', ':now')
            ->set('r.forwardError', 'NULL')
            ->where('r.id = :id')
            ->andWhere('(r.forwardAttemptedAt IS NULL OR r.forwardAttemptedAt < :stale OR r.forwardError IS NOT NULL OR r.forwardedAt >= r.forwardAttemptedAt)')
            ->setParameter('now', $now)
            ->setParameter('stale', $stale)
            ->setParameter('id', $id);
        if (!$force) {
            $qb->andWhere('r.forwardedAt IS NULL');
        }
        return $qb->getQuery()->execute() > 0;
    }

    /** Another report (any mailbox) of the very same message that was already forwarded. */
    public function findForwardedCopy(PhishingReport $report): ?PhishingReport
    {
        return $this->createQueryBuilder('r')
            ->where('r.sha256 = :sha')->andWhere('r.id != :id')->andWhere('r.forwardedAt IS NOT NULL')
            ->setParameter('sha', $report->getSha256())->setParameter('id', (int)$report->getId())
            ->orderBy('r.forwardedAt', 'DESC')->setMaxResults(1)
            ->getQuery()->getOneOrNullResult();
    }

    /**
     * Automatic mode: reports created between $since and $before that were
     * never attempted and are not marked as false positive / already reported.
     *
     * @return PhishingReport[]
     */
    public function findAutoForwardCandidates(\DateTime $since, \DateTime $before, int $limit): array
    {
        return $this->createQueryBuilder('r')
            ->where('r.createdAt >= :since')->andWhere('r.createdAt <= :before')
            ->andWhere('r.forwardAttemptedAt IS NULL')->andWhere('r.forwardedAt IS NULL')
            ->andWhere('r.status IN (:statuses)')
            ->setParameter('since', $since)->setParameter('before', $before)
            ->setParameter('statuses', [PhishingReport::STATUS_NEW, PhishingReport::STATUS_CONFIRMED])
            ->orderBy('r.createdAt', 'ASC')->setMaxResults($limit)
            ->getQuery()->getResult();
    }

    public function purgeOlderThan(\DateTime $before)
    {
        return $this->createQueryBuilder('r')->delete()
            ->where('r.lastReportedAt < :before')->setParameter('before', $before)
            ->getQuery()->execute();
    }
}
