<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;

class CronRunRepository extends EntityRepository
{
    public function findRecent($limit = 200, $command = null, $failedOnly = false)
    {
        $qb = $this->createQueryBuilder('r')
            ->orderBy('r.startedAt', \SortDirection::Descending)
            ->setMaxResults($limit);
        if ($command) {
            $qb->andWhere('r.command = :c')->setParameter('c', $command);
        }
        if ($failedOnly) {
            $qb->andWhere('r.exitCode IS NULL OR r.exitCode <> 0');
        }
        return $qb->getQuery()->getResult();
    }

    /** @return string[] */
    public function distinctCommands()
    {
        return array_column($this->createQueryBuilder('r')
            ->select('DISTINCT r.command')
            ->orderBy('r.command')
            ->getQuery()
            ->getScalarResult(), 'command');
    }

    public function purgeOlderThan(\DateTime $before)
    {
        return $this->createQueryBuilder('r')
            ->delete()
            ->where('r.startedAt < :before')
            ->setParameter('before', $before)
            ->getQuery()
            ->execute();
    }
}
