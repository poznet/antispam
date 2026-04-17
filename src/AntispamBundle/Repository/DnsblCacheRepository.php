<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;

class DnsblCacheRepository extends EntityRepository
{
    public function findFresh($ip, $zone)
    {
        return $this->findOneBy(['ip' => $ip, 'zone' => $zone]);
    }

    public function purgeExpired(\DateTime $before)
    {
        return $this->createQueryBuilder('c')
            ->delete()
            ->where('c.checkedAt < :before')
            ->setParameter('before', $before)
            ->getQuery()
            ->execute();
    }
}
