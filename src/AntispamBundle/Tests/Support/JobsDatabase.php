<?php

namespace AntispamBundle\Tests\Support;

use AntispamBundle\Entity\BackgroundJob;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\Jobs\JobQueue;
use AntispamBundle\Services\Jobs\JobWorker;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\Persistence\ManagerRegistry;

/**
 * In-memory SQLite database with the full entity schema, a real JobQueue and
 * a JobWorker factory - for background job tests.
 */
class JobsDatabase
{
    public EntityManager $em;
    public JobQueue $queue;

    public function __construct(?AuditLogger $audit = null)
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->queue = new JobQueue($this->em->getConnection(), $this->em, $audit);
    }

    /** @param iterable<\AntispamBundle\Services\Jobs\JobHandlerInterface> $handlers */
    public function worker(iterable $handlers, ?AuditLogger $audit = null, iterable $runtimeCaches = []): JobWorker
    {
        $em = $this->em;
        $registry = new class($em) implements ManagerRegistry {
            public function __construct(private EntityManager $em) {}
            public function getDefaultConnectionName(): string { return 'default'; }
            public function getConnection(?string $name = null): object { return $this->em->getConnection(); }
            public function getConnections(): array { return [$this->em->getConnection()]; }
            public function getConnectionNames(): array { return ['default' => 'default']; }
            public function getDefaultManagerName(): string { return 'default'; }
            public function getManager(?string $name = null): \Doctrine\Persistence\ObjectManager { return $this->em; }
            public function getManagers(): array { return [$this->em]; }
            public function resetManager(?string $name = null): \Doctrine\Persistence\ObjectManager { return $this->em; }
            public function getManagerNames(): array { return ['default' => 'default']; }
            public function getRepository(string $persistentObject, ?string $persistentManagerName = null): \Doctrine\Persistence\ObjectRepository { return $this->em->getRepository($persistentObject); }
            public function getManagerForClass(string $class): ?\Doctrine\Persistence\ObjectManager { return $this->em; }
        };
        return new JobWorker($this->em->getConnection(), $registry, $handlers, null, $audit, $runtimeCaches);
    }

    /** Raw row of a job. */
    public function row(int $id): array
    {
        return $this->em->getConnection()->fetchAssociative('SELECT * FROM ' . BackgroundJob::TABLE . ' WHERE id = ?', [$id]) ?: [];
    }

    public function update(int $id, array $data): void
    {
        $this->em->getConnection()->update(BackgroundJob::TABLE, $data, ['id' => $id]);
    }
}
