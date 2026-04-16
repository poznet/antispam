<?php

namespace AntispamBundle\Repository;

use Doctrine\ORM\EntityRepository;

class DnsblProviderRepository extends EntityRepository
{
    public function findEnabled()
    {
        return $this->findBy(['enabled' => true]);
    }
}
