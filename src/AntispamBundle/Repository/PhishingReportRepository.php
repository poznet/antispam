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
            $qb->andWhere('r.sender LIKE :q OR r.replyTo LIKE :q OR r.subject LIKE :q')
               ->setParameter('q', '%' . addcslashes(trim($filters['q']), '%_\\') . '%');
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

    public function purgeOlderThan(\DateTime $before)
    {
        return $this->createQueryBuilder('r')->delete()
            ->where('r.lastReportedAt < :before')->setParameter('before', $before)
            ->getQuery()->execute();
    }
}
