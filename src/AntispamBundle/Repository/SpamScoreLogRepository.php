<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;

class SpamScoreLogRepository extends EntityRepository
{
    public function findRecent($limit = 50, $accountEmail = null)
    {
        $qb = $this->createQueryBuilder('l')
            ->orderBy('l.scoredAt', 'DESC')
            ->setMaxResults($limit);
        if ($accountEmail) {
            $qb->andWhere('l.accountEmail = :e')->setParameter('e', $accountEmail);
        }
        return $qb->getQuery()->getResult();
    }

    public function statsByDecision(\DateTime $since = null)
    {
        $qb = $this->createQueryBuilder('l')
            ->select('l.decision AS decision, COUNT(l.id) AS cnt')
            ->groupBy('l.decision');
        if ($since) {
            $qb->andWhere('l.scoredAt >= :since')->setParameter('since', $since);
        }
        $out = ['ham' => 0, 'quarantine' => 0, 'spam' => 0, 'whitelisted' => 0];
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
            ->setParameter('since', $since)
            ->groupBy('day, decision')
            ->orderBy('day', 'ASC')
            ->getQuery()
            ->getArrayResult();
        return $rows;
    }
}
