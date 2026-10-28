<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\BackgroundJob;
use Doctrine\ORM\EntityRepository;

class BackgroundJobRepository extends EntityRepository
{
    /** @return BackgroundJob[] newest first */
    public function findRecent(int $limit = 200, ?string $status = null, ?string $type = null): array
    {
        $qb = $this->createQueryBuilder('j')
            ->orderBy('j.id', \SortDirection::Descending)
            ->setMaxResults($limit);
        if ($status === 'active') {
            $qb->andWhere('j.status IN (:active)')->setParameter('active', BackgroundJob::ACTIVE_STATUSES);
        } elseif ($status !== null) {
            $qb->andWhere('j.status = :s')->setParameter('s', $status);
        }
        if ($type !== null) {
            $qb->andWhere('j.type = :t')->setParameter('t', $type);
        }
        return $qb->getQuery()->getResult();
    }

    public function countActive(): int
    {
        return (int)$this->createQueryBuilder('j')
            ->select('COUNT(j.id)')
            ->where('j.status IN (:active)')
            ->setParameter('active', BackgroundJob::ACTIVE_STATUSES)
            ->getQuery()
            ->getSingleScalarResult();
    }
}
