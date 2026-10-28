<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\QueryBuilder;

class AuditLogRepository extends EntityRepository
{
    /**
     * @param array{from?: ?\DateTimeInterface, to?: ?\DateTimeInterface, actor?: ?string, action?: ?string, mailbox?: ?string} $filters
     *
     * @return array{items: array, total: int}
     */
    public function search(array $filters, int $page = 1, int $perPage = 50): array
    {
        $qb = $this->filtered($filters);
        $total = (int)(clone $qb)->select('COUNT(a.id)')->getQuery()->getSingleScalarResult();
        $items = $qb->orderBy('a.createdAt', 'DESC')->addOrderBy('a.id', 'DESC')
            ->setFirstResult(max(0, ($page - 1) * $perPage))
            ->setMaxResults($perPage)
            ->getQuery()->getResult();

        return ['items' => $items, 'total' => $total];
    }

    /**
     * Rows for the CSV export: the newest $limit rows of the filter, newest first.
     *
     * @return iterable<\AntispamBundle\Entity\AuditLog>
     */
    public function export(array $filters, int $limit): iterable
    {
        return $this->filtered($filters)->orderBy('a.createdAt', 'DESC')->addOrderBy('a.id', 'DESC')
            ->setMaxResults($limit)->getQuery()->toIterable();
    }

    /** @return string[] */
    public function distinctActions(): array
    {
        return array_column($this->createQueryBuilder('a')
            ->select('DISTINCT a.action')->orderBy('a.action')
            ->getQuery()->getScalarResult(), 'action');
    }

    public function purgeOlderThan(\DateTimeInterface $before): int
    {
        return (int)$this->createQueryBuilder('a')->delete()
            ->where('a.createdAt < :before')->setParameter('before', $before)
            ->getQuery()->execute();
    }

    public function countOlderThan(\DateTimeInterface $before): int
    {
        return (int)$this->createQueryBuilder('a')->select('COUNT(a.id)')
            ->where('a.createdAt < :before')->setParameter('before', $before)
            ->getQuery()->getSingleScalarResult();
    }

    private function filtered(array $filters): QueryBuilder
    {
        $qb = $this->createQueryBuilder('a');
        if (!empty($filters['from'])) {
            $qb->andWhere('a.createdAt >= :from')->setParameter('from', $filters['from']);
        }
        if (!empty($filters['to'])) {
            $qb->andWhere('a.createdAt < :to')->setParameter('to', $filters['to']);
        }
        if (($filters['actor'] ?? '') !== '' && $filters['actor'] !== null) {
            $qb->andWhere('a.actor LIKE :actor')->setParameter('actor', '%' . addcslashes($filters['actor'], '%_\\') . '%');
        }
        if (($filters['action'] ?? '') !== '' && $filters['action'] !== null) {
            // "rule." matches every action of the group.
            if (str_ends_with($filters['action'], '.')) {
                $qb->andWhere('a.action LIKE :action')->setParameter('action', addcslashes($filters['action'], '%_\\') . '%');
            } else {
                $qb->andWhere('a.action = :action')->setParameter('action', $filters['action']);
            }
        }
        if (($filters['mailbox'] ?? '') !== '' && $filters['mailbox'] !== null) {
            $qb->andWhere('a.mailbox LIKE :mailbox')->setParameter('mailbox', '%' . addcslashes($filters['mailbox'], '%_\\') . '%');
        }
        return $qb;
    }
}
