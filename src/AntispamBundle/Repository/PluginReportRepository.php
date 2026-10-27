<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;

class PluginReportRepository extends EntityRepository
{
    /** @param string|null $who 'anonymous' | 'account' | null (all) */
    public function findRecent($limit = 200, $verdict = null, $who = null)
    {
        $qb = $this->createQueryBuilder('r')
            ->orderBy('r.reportedAt', \SortDirection::Descending)
            ->setMaxResults($limit);
        if ($verdict) {
            $qb->andWhere('r.verdict = :v')->setParameter('v', $verdict);
        }
        if ($who === 'anonymous') {
            $qb->andWhere('r.accountEmail IS NULL');
        } elseif ($who === 'account') {
            $qb->andWhere('r.accountEmail IS NOT NULL');
        }
        return $qb->getQuery()->getResult();
    }

    /** @return array{spam:int, ham:int, anonymous:int, senders:int} */
    public function stats(\DateTime $since)
    {
        $row = $this->createQueryBuilder('r')
            ->select("SUM(CASE WHEN r.verdict = 'spam' THEN 1 ELSE 0 END) AS spam")
            ->addSelect("SUM(CASE WHEN r.verdict = 'ham' THEN 1 ELSE 0 END) AS ham")
            ->addSelect('SUM(CASE WHEN r.accountEmail IS NULL THEN 1 ELSE 0 END) AS anonymous')
            ->addSelect('COUNT(DISTINCT r.sender) AS senders')
            ->andWhere('r.reportedAt >= :since')
            ->setParameter('since', $since)
            ->getQuery()
            ->getSingleResult();
        return array_map('intval', $row);
    }

    /** Most reported spam senders. */
    public function topSenders(\DateTime $since, $limit = 10)
    {
        return $this->createQueryBuilder('r')
            ->select('r.sender AS sender, COUNT(r.id) AS cnt, MAX(r.reportedAt) AS last')
            ->andWhere('r.reportedAt >= :since')
            ->andWhere("r.verdict = 'spam'")
            ->andWhere('r.sender IS NOT NULL')
            ->setParameter('since', $since)
            ->groupBy('r.sender')
            ->orderBy('cnt', \SortDirection::Descending)
            ->setMaxResults($limit)
            ->getQuery()
            ->getArrayResult();
    }

    public function purgeOlderThan(\DateTime $before)
    {
        return $this->createQueryBuilder('r')
            ->delete()
            ->where('r.reportedAt < :before')
            ->setParameter('before', $before)
            ->getQuery()
            ->execute();
    }
}
