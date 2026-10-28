<?php

namespace AntispamBundle\Tests\Support;

use Doctrine\ORM\EntityRepository;

/**
 * Minimal stand-in for a Doctrine repository: findBy/findOneBy over an array
 * of entities, with Doctrine's semantics for array values (IN) and MySQL's
 * case-insensitive string comparison. Records every criteria it was asked.
 */
class InMemoryRepository extends EntityRepository
{
    /** @var object[] */
    public array $items = [];
    /** @var array[] */
    public array $queries = [];

    public function __construct(array $items = [])
    {
        // Deliberately no parent::__construct() - no EntityManager needed.
        $this->items = array_values($items);
    }

    public function add(object $item): void
    {
        $this->items[] = $item;
    }

    public function find(mixed $id, $lockMode = null, $lockVersion = null): object|null
    {
        foreach ($this->items as $item) {
            if (method_exists($item, 'getId') && $item->getId() == $id) {
                return $item;
            }
        }
        return null;
    }

    public function findAll(): array
    {
        return $this->findBy([]);
    }

    public function findBy(array $criteria, array|null $orderBy = null, int|null $limit = null, int|null $offset = null): array
    {
        $this->queries[] = $criteria;
        $out = [];
        foreach ($this->items as $item) {
            foreach ($criteria as $field => $expected) {
                $actual = (string)$item->{'get' . ucfirst($field)}();
                $allowed = is_array($expected) ? $expected : [$expected];
                $hit = false;
                foreach ($allowed as $value) {
                    if (strcasecmp($actual, (string)$value) === 0) {
                        $hit = true;
                        break;
                    }
                }
                if (!$hit) {
                    continue 2;
                }
            }
            $out[] = $item;
        }
        return $out;
    }

    public function findOneBy(array $criteria, array|null $orderBy = null): object|null
    {
        return $this->findBy($criteria)[0] ?? null;
    }
}
