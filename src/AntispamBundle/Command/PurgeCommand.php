<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConfigService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Housekeeping for tables that otherwise grow forever:
 *
 *   - antispam_spam_score_log: rows older than `scorelog.retention_days`
 *     (default 180, 0 = keep forever)
 *   - antispam_dnsbl_cache: entries no provider would still use (older than
 *     the longest provider cache TTL, at least one day)
 *
 * Run daily, e.g. through the cron log wrapper (the Docker scheduler does):
 *
 *     php bin/console antispam:cron:run antispam:purge
 */
#[AsCommand(name: 'antispam:purge', description: 'Delete old score log rows and expired DNSBL cache entries')]
class PurgeCommand extends Command
{
    const CONFIG_RETENTION = 'scorelog.retention_days';
    const DEFAULT_RETENTION_DAYS = 180;

    /** DNSBL cache rows are kept at least this long, whatever the provider TTLs. */
    const MIN_DNSBL_AGE = 86400;

    public function __construct(private EntityManagerInterface $em, private ConfigService $config)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('days', null, InputOption::VALUE_REQUIRED, 'Score log retention in days (overrides ' . self::CONFIG_RETENTION . '; 0 = keep forever)')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only report what would be deleted');
    }

    /** Effective score log retention in days; 0 = keep forever. */
    public function getRetentionDays(): int
    {
        $v = $this->config->get(self::CONFIG_RETENTION);
        if ($v === null || $v === '' || !is_numeric($v)) {
            return self::DEFAULT_RETENTION_DAYS;
        }
        return max(0, (int)$v);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $days = $input->getOption('days');
        if ($days !== null && (!is_numeric($days) || (int)$days < 0)) {
            $output->writeln('<error>--days must be a number >= 0</error>');
            return Command::INVALID;
        }
        $days = $days !== null ? (int)$days : $this->getRetentionDays();
        $dryRun = (bool)$input->getOption('dry-run');

        if ($days === 0) {
            $output->writeln('Score log: retention 0 (keep forever), nothing deleted.');
        } else {
            $before = new \DateTime('-' . $days . ' days');
            $n = $dryRun ? $this->countScoreLogBefore($before) : $this->em->getRepository(SpamScoreLog::class)->purgeOlderThan($before);
            $output->writeln(sprintf('Score log: %s %d row(s) older than %d days (before %s).', $dryRun ? 'would delete' : 'deleted', $n, $days, $before->format('Y-m-d H:i')));
        }

        $ttl = max(self::MIN_DNSBL_AGE, $this->maxDnsblTtl());
        $before = (new \DateTime())->setTimestamp(time() - $ttl);
        $n = $dryRun ? $this->countDnsblBefore($before) : $this->em->getRepository(DnsblCache::class)->purgeExpired($before);
        $output->writeln(sprintf('DNSBL cache: %s %d expired entr%s (checked before %s).', $dryRun ? 'would delete' : 'deleted', $n, $n === 1 ? 'y' : 'ies', $before->format('Y-m-d H:i')));

        return Command::SUCCESS;
    }

    private function maxDnsblTtl(): int
    {
        try {
            return (int)$this->em->createQueryBuilder()
                ->select('MAX(p.cacheTtl)')
                ->from(DnsblProvider::class, 'p')
                ->getQuery()->getSingleScalarResult();
        } catch (\Throwable $e) {
            return 0;
        }
    }

    private function countScoreLogBefore(\DateTime $before): int
    {
        return (int)$this->em->createQueryBuilder()
            ->select('COUNT(l.id)')->from(SpamScoreLog::class, 'l')
            ->where('l.scoredAt < :before')->setParameter('before', $before)
            ->getQuery()->getSingleScalarResult();
    }

    private function countDnsblBefore(\DateTime $before): int
    {
        return (int)$this->em->createQueryBuilder()
            ->select('COUNT(c.id)')->from(DnsblCache::class, 'c')
            ->where('c.checkedAt < :before')->setParameter('before', $before)
            ->getQuery()->getSingleScalarResult();
    }
}
