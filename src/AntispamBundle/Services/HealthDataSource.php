<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\CronRun;
use AntispamBundle\Entity\SpamScoreLog;
use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Database / filesystem facts the health checks are evaluated on. Kept apart
 * from HealthService so the checks themselves can be tested without a
 * database (every method here is a thin query).
 */
class HealthDataSource
{
    public function __construct(
        private EntityManagerInterface $em,
        #[Autowire('%kernel.project_dir%/var')] private string $varDir,
    ) {
    }

    /** Throws when the database is unreachable. */
    public function pingDatabase(): void
    {
        $this->em->getConnection()->executeQuery('SELECT 1')->fetchOne();
    }

    /** @return Account[] */
    public function accounts(): array
    {
        return $this->em->getRepository(Account::class)->findBy([], ['id' => 'ASC']);
    }

    /**
     * Newest run of every command in the cron log.
     *
     * @return array<string, CronRun> command => run
     */
    public function lastCronRuns(): array
    {
        $ids = array_map('intval', array_column($this->em->createQueryBuilder()
            ->select('MAX(r.id) AS id')
            ->from(CronRun::class, 'r')
            ->groupBy('r.command')
            ->getQuery()
            ->getScalarResult(), 'id'));
        if (!$ids) {
            return [];
        }
        $out = [];
        foreach ($this->em->getRepository(CronRun::class)->findBy(['id' => $ids]) as $run) {
            $out[$run->getCommand()] = $run;
        }
        return $out;
    }

    /**
     * Newest runs of $command, newest first.
     *
     * @return CronRun[]
     */
    public function recentCronRuns(string $command, int $limit = 6): array
    {
        return $this->em->getRepository(CronRun::class)->findBy(['command' => $command], ['startedAt' => 'DESC', 'id' => 'DESC'], $limit);
    }

    /** Newest run of $command that ended with exit code 0. */
    public function lastSuccessfulCronRun(string $command): ?CronRun
    {
        return $this->em->getRepository(CronRun::class)->findOneBy(['command' => $command, 'exitCode' => 0], ['startedAt' => 'DESC']);
    }

    /**
     * Runs per command since $since: total and failed (finished with a
     * non-zero exit code).
     *
     * @return array<string, array{runs:int, failures:int}>
     */
    public function cronStatsSince(\DateTimeInterface $since): array
    {
        $rows = $this->em->createQueryBuilder()
            ->select('r.command AS command, COUNT(r.id) AS runs, SUM(CASE WHEN r.exitCode IS NOT NULL AND r.exitCode <> 0 THEN 1 ELSE 0 END) AS failures')
            ->from(CronRun::class, 'r')
            ->where('r.startedAt >= :since')
            ->setParameter('since', \DateTime::createFromInterface($since))
            ->groupBy('r.command')
            ->getQuery()
            ->getScalarResult();
        $out = [];
        foreach ($rows as $row) {
            $out[$row['command']] = ['runs' => (int)$row['runs'], 'failures' => (int)$row['failures']];
        }
        return $out;
    }

    /** Size of the application database in bytes, null when unknown (not MySQL/MariaDB). */
    public function databaseSize(): ?int
    {
        $conn = $this->em->getConnection();
        if (!$conn->getDatabasePlatform() instanceof AbstractMySQLPlatform) {
            return null;
        }
        $size = $conn->fetchOne('SELECT SUM(data_length + index_length) FROM information_schema.tables WHERE table_schema = DATABASE()');
        return $size === false || $size === null ? null : (int)$size;
    }

    /** @return array{free:?int, total:?int, path:string} */
    public function diskSpace(): array
    {
        $path = is_dir($this->varDir) ? $this->varDir : dirname($this->varDir);
        $free = @disk_free_space($path);
        $total = @disk_total_space($path);
        return [
            'free' => $free === false ? null : (int)$free,
            'total' => $total === false ? null : (int)$total,
            'path' => $path,
        ];
    }

    /**
     * Statements `doctrine:schema:update --force` would still run, without
     * DROPs (the boot-time update only adds; dropped legacy columns are not
     * drift). Introspects the whole schema, so full check only.
     *
     * @return string[]
     */
    public function pendingSchemaChanges(): array
    {
        $sql = (new SchemaTool($this->em))->getUpdateSchemaSql($this->em->getMetadataFactory()->getAllMetadata());
        return array_values(array_filter($sql, fn($s) => !preg_match('/^\s*(ALTER TABLE \S+ DROP|DROP )/i', $s)));
    }

    /** @return array<string,int> decision => count over the score log since $since */
    public function decisionsSince(\DateTimeInterface $since): array
    {
        return $this->em->getRepository(SpamScoreLog::class)->statsByDecision(\DateTime::createFromInterface($since));
    }

    /** @return array<string,int> account e-mail => messages quarantined since $since */
    public function quarantinedSince(\DateTimeInterface $since): array
    {
        $rows = $this->em->createQueryBuilder()
            ->select('l.accountEmail AS account, COUNT(l.id) AS cnt')
            ->from(SpamScoreLog::class, 'l')
            ->where('l.scoredAt >= :since')
            ->andWhere('l.outcome = :outcome')
            ->andWhere('l.initialScan = false')
            ->setParameter('since', \DateTime::createFromInterface($since))
            ->setParameter('outcome', SpamScoreLog::OUTCOME_QUARANTINED)
            ->groupBy('l.accountEmail')
            ->getQuery()
            ->getScalarResult();
        $out = [];
        foreach ($rows as $row) {
            $out[(string)$row['account']] = (int)$row['cnt'];
        }
        return $out;
    }
}
