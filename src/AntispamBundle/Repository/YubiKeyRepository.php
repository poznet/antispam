<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\User;
use AntispamBundle\Entity\YubiKey;
use Doctrine\ORM\EntityRepository;

/** @extends EntityRepository<YubiKey> */
class YubiKeyRepository extends EntityRepository
{
    /** @return YubiKey[] */
    public function findByUser(User $user): array
    {
        if ($user->getId() === null) {
            return [];
        }
        return $this->findBy(['user' => $user], ['createdAt' => 'ASC']);
    }

    public function findOneByPublicId(string $publicId): ?YubiKey
    {
        return $this->findOneBy(['publicId' => $publicId]);
    }

    /** @return array<int, int> user id => number of keys */
    public function countByUser(): array
    {
        $rows = $this->createQueryBuilder('k')
            ->select('IDENTITY(k.user) AS uid, COUNT(k.id) AS n')
            ->groupBy('k.user')
            ->getQuery()->getArrayResult();
        $out = [];
        foreach ($rows as $row) {
            $out[(int)$row['uid']] = (int)$row['n'];
        }
        return $out;
    }

    public function deleteByUser(User $user): int
    {
        return (int)$this->createQueryBuilder('k')->delete()
            ->where('k.user = :user')->setParameter('user', $user)
            ->getQuery()->execute();
    }
}
