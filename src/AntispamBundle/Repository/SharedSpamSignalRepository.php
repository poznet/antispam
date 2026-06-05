<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\SharedSpamSignal;
use Doctrine\ORM\EntityRepository;

class SharedSpamSignalRepository extends EntityRepository
{
    public function findOneByTypeHash($type, $hash)
    {
        return $this->findOneBy(['type' => $type, 'hash' => $hash]);
    }

    /**
     * Batch lookup for a list of {type, hash} pairs. Returns matching entities
     * indexed by "type:hash" so callers can avoid a query per pair.
     *
     * @param array<int, array{type:string, hash:string}> $pairs
     * @return array<string, SharedSpamSignal>
     */
    public function findByTypeHashPairs(array $pairs)
    {
        if (!$pairs) {
            return [];
        }
        $byType = [];
        foreach ($pairs as $p) {
            $type = $p['type'] ?? null;
            $hash = $p['hash'] ?? null;
            if ($type === null || $hash === null) { continue; }
            $byType[$type][$hash] = true;
        }
        if (!$byType) {
            return [];
        }

        $qb = $this->createQueryBuilder('s');
        $orX = $qb->expr()->orX();
        $i = 0;
        foreach ($byType as $type => $hashes) {
            $tParam = 't' . $i;
            $hParam = 'h' . $i;
            $orX->add($qb->expr()->andX(
                $qb->expr()->eq('s.type', ':' . $tParam),
                $qb->expr()->in('s.hash', ':' . $hParam)
            ));
            $qb->setParameter($tParam, $type)
                ->setParameter($hParam, array_keys($hashes));
            $i++;
        }
        $qb->andWhere($orX);

        $out = [];
        foreach ($qb->getQuery()->getResult() as $entity) {
            $out[$entity->getType() . ':' . $entity->getHash()] = $entity;
        }
        return $out;
    }

    /**
     * Locally-detected signals with id greater than $afterId, for pushing to a
     * remote hub. Ordered by id so the caller can checkpoint the last id sent.
     */
    public function findLocalAfterId($afterId, $limit = 1000)
    {
        return $this->createQueryBuilder('s')
            ->andWhere('s.origin = :origin')->setParameter('origin', SharedSpamSignal::ORIGIN_LOCAL)
            ->andWhere('s.id > :afterId')->setParameter('afterId', (int)$afterId)
            ->orderBy('s.id', 'ASC')
            ->setMaxResults((int)$limit)
            ->getQuery()->getResult();
    }

    /**
     * Signals updated after $since, for serving an incremental pull. Ordered by
     * updatedAt so clients can checkpoint on the response's "now" timestamp.
     */
    public function findUpdatedSince(\DateTime $since = null, $limit = 5000)
    {
        $qb = $this->createQueryBuilder('s')
            ->orderBy('s.updatedAt', 'ASC')
            ->addOrderBy('s.id', 'ASC')
            ->setMaxResults((int)$limit);
        if ($since) {
            $qb->andWhere('s.updatedAt > :since')->setParameter('since', $since);
        }
        return $qb->getQuery()->getResult();
    }

    /**
     * @return array{local:int, remote:int, total:int}
     */
    public function countByOrigin()
    {
        $rows = $this->createQueryBuilder('s')
            ->select('s.origin AS origin, COUNT(s.id) AS cnt')
            ->groupBy('s.origin')
            ->getQuery()->getArrayResult();
        $out = ['local' => 0, 'remote' => 0, 'total' => 0];
        foreach ($rows as $row) {
            $out[$row['origin']] = (int)$row['cnt'];
            $out['total'] += (int)$row['cnt'];
        }
        return $out;
    }
}
