<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\PhishingReport;
use Doctrine\ORM\EntityRepository;

class PhishingReportRepository extends EntityRepository
{
    /** Columns for the list view - everything except the raw source. */
    private const LIST_FIELDS = 'r.id, r.createdAt, r.lastReportedAt, r.reportCount, r.accountEmail, r.client, r.sender, r.senderName, r.replyTo, r.subject, r.size, r.truncated, r.status';

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

    public function purgeOlderThan(\DateTime $before)
    {
        return $this->createQueryBuilder('r')->delete()
            ->where('r.lastReportedAt < :before')->setParameter('before', $before)
            ->getQuery()->execute();
    }
}
