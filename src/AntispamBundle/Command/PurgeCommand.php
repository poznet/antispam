<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\DnsblCache;
use AntispamBundle\Entity\DnsblProvider;
use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\AuditLogger;
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
 *   - antispam_audit_log: rows older than `audit.retention_days` (default 365)
 *   - antispam_bayes_message / antispam_bayes_token: learned-message
 *     fingerprints older than `bayes.message_retention_days` (365), tokens
 *     seen once and untouched for `bayes.token_retention_days` (180), rows of
 *     deleted mailboxes
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

    public function __construct(private EntityManagerInterface $em, private ConfigService $config, private ?\AntispamBundle\Services\Bayes\BayesService $bayes = null)
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

        // --- Audit log (antispam_audit_log): own retention, not affected by --days.
        $this->purgeAuditLog($dryRun, $output);
        // --- end audit log

        // --- Bayes classifier (docs/bayes.md): own retention, not affected by --days.
        if ($this->bayes && !$dryRun) {
            try {
                $r = $this->bayes->purge();
                $output->writeln(sprintf('Bayes: deleted %d learned-message fingerprint(s), %d rare stale token(s), %d row(s) of deleted mailboxes.', $r['messages'], $r['tokens'], $r['orphans']));
            } catch (\Throwable $e) {
                $output->writeln('<comment>Bayes: purge failed (' . $e->getMessage() . ')</comment>');
            }
        } elseif ($this->bayes) {
            $output->writeln('Bayes: skipped in --dry-run.');
        }
        // --- end Bayes

        return Command::SUCCESS;
    }

    /** Audit log rows older than `audit.retention_days` (default 365, 0 = keep forever). */
    private function purgeAuditLog(bool $dryRun, OutputInterface $output): void
    {
        $v = $this->config->get(AuditLogger::CONFIG_RETENTION);
        $days = $v === null || $v === '' || !is_numeric($v) ? AuditLogger::DEFAULT_RETENTION_DAYS : max(0, (int)$v);
        if ($days === 0) {
            $output->writeln('Audit log: retention 0 (keep forever), nothing deleted.');
            return;
        }
        $before = new \DateTime('-' . $days . ' days');
        $repo = $this->em->getRepository(AuditLog::class);
        $n = $dryRun ? $repo->countOlderThan($before) : $repo->purgeOlderThan($before);
        $output->writeln(sprintf('Audit log: %s %d row(s) older than %d days (before %s).', $dryRun ? 'would delete' : 'deleted', $n, $days, $before->format('Y-m-d H:i')));
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
