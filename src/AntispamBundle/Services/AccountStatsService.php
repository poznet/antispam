<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AccountDailyStat;
use AntispamBundle\Entity\SpamScoreLog;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * "Statystyki konta" (docs/account-stats.md):
 *
 *   - record(): adds the counters of a scan / rescan / retroactive pass to the
 *     account's row of the day (antispam_account_daily_stat) - IMAP and SSH;
 *   - totals() / daily(): those counters for a period;
 *   - scoreLog(): what the score log knows about the mailbox (IMAP scans and
 *     plugin checks - SSH agents keep their own log, read with SshService::runStats()).
 *
 * Plain DBAL: a scan may have reset / closed the EntityManager, the stats must
 * still be written, and a failure here never fails the scan.
 */
class AccountStatsService
{
    public const TABLE = 'antispam_account_daily_stat';
    /** Score log rows read for the top senders / rules of a period. */
    public const MAX_ROWS = 20000;

    public function __construct(
        private EntityManagerInterface $em,
        private ?LoggerInterface $logger = null,
    ) {
    }

    private function db(): Connection
    {
        return $this->em->getConnection();
    }

    /**
     * @param array $result scan counters (checked, whitelisted, moved_to_spam, errors[]...)
     */
    public function record(Account|int $account, string $kind, array $result, ?\DateTimeInterface $at = null): void
    {
        $id = $account instanceof Account ? $account->getId() : $account;
        if (!$id || !isset(AccountDailyStat::KINDS[$kind])) {
            return;
        }
        $add = ['passes' => 1];
        foreach (AccountDailyStat::COUNTERS as $k) {
            if ($k === 'passes') {
                continue;
            }
            $v = $k === 'errors' ? (is_array($result['errors'] ?? null) ? count($result['errors']) : (int)($result['errors'] ?? 0)) : (int)($result[$k] ?? 0);
            $add[$k] = max(0, $v);
        }
        $day = \DateTimeImmutable::createFromInterface($at ?? new \DateTimeImmutable())->format('Y-m-d');
        try {
            $this->upsert((int)$id, $day, $kind, $add);
        } catch (\Throwable $e) {
            $this->logger?->warning('antispam: account stats not recorded', ['account' => $id, 'error' => $e->getMessage()]);
        }
    }

    private function upsert(int $id, string $day, string $kind, array $add): void
    {
        $db = $this->db();
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $set = [];
        $params = [];
        foreach ($add as $k => $v) {
            $set[] = $k . ' = ' . $k . ' + ?';
            $params[] = $v;
        }
        $update = 'UPDATE ' . self::TABLE . ' SET ' . implode(', ', $set) . ', updated_at = ? WHERE account_id = ? AND day = ? AND kind = ?';
        $where = [$now, $id, $day, $kind];
        if ($db->executeStatement($update, array_merge($params, $where)) > 0) {
            return;
        }
        try {
            $db->insert(self::TABLE, ['account_id' => $id, 'day' => $day, 'kind' => $kind, 'updated_at' => $now] + $add);
        } catch (UniqueConstraintViolationException) {
            // Another process inserted the row of the day in between.
            $db->executeStatement($update, array_merge($params, $where));
        }
    }

    /** Drops the counters of a deleted account. */
    public function forget(int $accountId): void
    {
        try {
            $this->db()->delete(self::TABLE, ['account_id' => $accountId]);
        } catch (\Throwable $e) {
            $this->logger?->warning('antispam: account stats not removed', ['account' => $accountId, 'error' => $e->getMessage()]);
        }
    }

    /** Start of a period of $days days (null = everything). */
    public static function since(?int $days): ?\DateTimeImmutable
    {
        return $days ? (new \DateTimeImmutable('today'))->modify('-' . ($days - 1) . ' days') : null;
    }

    /**
     * @return array{all: array<string,int>, kinds: array<string, array<string,int>>, first_day: ?string, last_update: ?string}
     */
    public function totals(int $accountId, ?\DateTimeImmutable $since): array
    {
        $cols = implode(', ', array_map(fn ($c) => 'SUM(' . $c . ') AS ' . $c, AccountDailyStat::COUNTERS));
        $sql = 'SELECT kind, ' . $cols . ', MIN(day) AS first_day, MAX(updated_at) AS last_update FROM ' . self::TABLE . ' WHERE account_id = ?';
        $params = [$accountId];
        if ($since) {
            $sql .= ' AND day >= ?';
            $params[] = $since->format('Y-m-d');
        }
        $rows = $this->db()->fetchAllAssociative($sql . ' GROUP BY kind', $params);
        $zero = array_fill_keys(AccountDailyStat::COUNTERS, 0);
        $out = ['all' => $zero, 'kinds' => [], 'first_day' => null, 'last_update' => null];
        foreach ($rows as $row) {
            $c = $zero;
            foreach (AccountDailyStat::COUNTERS as $k) {
                $c[$k] = (int)$row[$k];
                $out['all'][$k] += $c[$k];
            }
            $out['kinds'][$row['kind']] = $c;
            if ($row['first_day'] && ($out['first_day'] === null || $row['first_day'] < $out['first_day'])) {
                $out['first_day'] = (string)$row['first_day'];
            }
            if ($row['last_update'] && ($out['last_update'] === null || $row['last_update'] > $out['last_update'])) {
                $out['last_update'] = (string)$row['last_update'];
            }
        }
        // Fixed order of the kinds.
        $out['kinds'] = array_intersect_key(array_replace(array_fill_keys(array_keys(AccountDailyStat::KINDS), null), $out['kinds']), $out['kinds']);
        return $out;
    }

    /**
     * One entry per day of the period (oldest first), the given kinds summed
     * (default: new mail only - a rescan of thousands of old messages would
     * flatten the chart).
     *
     * @param string[] $kinds
     *
     * @return array<string, array<string,int>> 'Y-m-d' => counters
     */
    public function daily(int $accountId, int $days, array $kinds = [AccountDailyStat::KIND_SCAN, AccountDailyStat::KIND_INITIAL]): array
    {
        $since = self::since($days);
        $out = [];
        for ($d = $since; $d <= new \DateTimeImmutable('today'); $d = $d->modify('+1 day')) {
            $out[$d->format('Y-m-d')] = array_fill_keys(AccountDailyStat::COUNTERS, 0);
        }
        $cols = implode(', ', array_map(fn ($c) => 'SUM(' . $c . ') AS ' . $c, AccountDailyStat::COUNTERS));
        $kinds = array_values(array_intersect($kinds, array_keys(AccountDailyStat::KINDS))) ?: [AccountDailyStat::KIND_SCAN];
        $rows = $this->db()->fetchAllAssociative('SELECT day, ' . $cols . ' FROM ' . self::TABLE . ' WHERE account_id = ? AND day >= ? AND kind IN ('
            . implode(', ', array_fill(0, count($kinds), '?')) . ') GROUP BY day', array_merge([$accountId, $since->format('Y-m-d')], $kinds));
        foreach ($rows as $row) {
            $day = substr((string)$row['day'], 0, 10);
            if (isset($out[$day])) {
                foreach (AccountDailyStat::COUNTERS as $k) {
                    $out[$day][$k] = (int)$row[$k];
                }
            }
        }
        return $out;
    }

    /**
     * Score log of the mailbox in the period: decisions per source, where the
     * messages went, top senders / domains / rules of spam + quarantine, the
     * newest spam / quarantine entries.
     */
    public function scoreLog(string $email, ?\DateTimeImmutable $since): array
    {
        $db = $this->db();
        $where = 'account_email = ?';
        $params = [$email];
        if ($since) {
            $where .= ' AND scored_at >= ?';
            $params[] = $since->format('Y-m-d H:i:s');
        }
        $out = ['decisions' => [], 'sources' => [], 'outcomes' => [], 'total' => 0, 'senders' => [], 'domains' => [], 'rules' => [], 'categories' => [], 'recent' => [], 'sampled' => false];
        foreach ($db->fetchAllAssociative('SELECT decision, source, initial_scan, COUNT(*) AS cnt FROM antispam_spam_score_log WHERE ' . $where . ' GROUP BY decision, source, initial_scan', $params) as $row) {
            $source = $row['initial_scan'] && ($row['source'] ?? '') !== SpamScoreLog::SOURCE_RESCAN ? 'initial' : ((string)($row['source'] ?? '') ?: SpamScoreLog::SOURCE_SCAN);
            $n = (int)$row['cnt'];
            $out['decisions'][$row['decision']] = ($out['decisions'][$row['decision']] ?? 0) + $n;
            $out['sources'][$source][$row['decision']] = ($out['sources'][$source][$row['decision']] ?? 0) + $n;
            $out['total'] += $n;
        }
        foreach ($db->fetchAllAssociative('SELECT outcome, COUNT(*) AS cnt FROM antispam_spam_score_log WHERE ' . $where . ' AND outcome IS NOT NULL GROUP BY outcome', $params) as $row) {
            $out['outcomes'][$row['outcome']] = (int)$row['cnt'];
        }

        $bad = [SpamScoreLog::DECISION_SPAM, SpamScoreLog::DECISION_QUARANTINE];
        $rows = $db->fetchAllAssociative('SELECT sender, reasons FROM antispam_spam_score_log WHERE ' . $where . ' AND decision IN (?, ?) ORDER BY id DESC LIMIT ' . self::MAX_ROWS,
            array_merge($params, $bad));
        $out['sampled'] = count($rows) >= self::MAX_ROWS;
        $agg = self::aggregate($rows);
        $out = array_replace($out, $agg);

        foreach ($db->fetchAllAssociative('SELECT id, sender, subject, score, decision, source, outcome, scored_at FROM antispam_spam_score_log WHERE ' . $where
            . ' AND decision IN (?, ?) ORDER BY id DESC LIMIT 30', array_merge($params, $bad)) as $row) {
            $out['recent'][] = $row;
        }
        return $out;
    }

    /**
     * Top senders, sender domains, rules and rule categories of score log rows
     * (sender, reasons JSON [{rule, score}]) - shared with the agent's `stats`.
     *
     * @param iterable<array{sender: ?string, reasons: ?string}> $rows
     */
    public static function aggregate(iterable $rows, int $top = 15): array
    {
        $senders = $domains = $rules = $categories = [];
        foreach ($rows as $row) {
            $sender = strtolower(trim((string)($row['sender'] ?? '')));
            if ($sender !== '') {
                $senders[$sender] = ($senders[$sender] ?? 0) + 1;
                $at = strrpos($sender, '@');
                if ($at !== false) {
                    $domain = substr($sender, $at + 1);
                    $domains[$domain] = ($domains[$domain] ?? 0) + 1;
                }
            }
            $reasons = json_decode((string)($row['reasons'] ?? ''), true);
            $seen = [];
            foreach (is_array($reasons) ? $reasons : [] as $reason) {
                $rule = is_array($reason) ? trim((string)($reason['rule'] ?? '')) : '';
                if ($rule === '' || isset($seen[$rule])) {
                    continue;
                }
                $seen[$rule] = true;
                $rules[$rule] = ($rules[$rule] ?? 0) + 1;
                $cat = self::ruleCategory($rule);
                $categories[$cat] = ($categories[$cat] ?? 0) + 1;
            }
        }
        $topN = function (array $counts) use ($top) {
            arsort($counts);
            return array_slice($counts, 0, $top, true);
        };
        return ['senders' => $topN($senders), 'domains' => $topN($domains), 'rules' => $topN($rules), 'categories' => $topN($categories)];
    }

    /** "blacklist:*.ru (wildcard)" -> "blacklist", "complex_rule:#3 X (spam)" -> "complex_rule". */
    public static function ruleCategory(string $rule): string
    {
        $cat = strtolower((string)preg_replace('~[:\s(].*$~s', '', $rule));
        return $cat !== '' ? $cat : 'inne';
    }

    public const CATEGORY_LABELS = [
        'blacklist' => 'czarna lista (domena)',
        'email_blacklist' => 'czarna lista (adres)',
        'complex_rule' => 'reguła złożona',
        'dnsbl' => 'DNSBL (IP na czarnej liście)',
        'shared_feed' => 'wspólna baza spamu',
        'bayes' => 'klasyfikator Bayesa',
        'virustotal' => 'VirusTotal',
        'clamav' => 'ClamAV',
        'cert_hole' => 'lista CERT Polska',
        'lookalike_domain' => 'domena podobna do Twojej',
        'impersonation_vip' => 'podszywanie się pod osobę (VIP)',
        'impersonation_display_address' => 'fałszywy adres w nazwie nadawcy',
        'display_name_embedded_address' => 'adres w nazwie nadawcy',
        'internal_domain_spoof' => 'podszywanie się pod własną domenę',
        'header_cap' => 'limit punktów z nagłówków',
        'retroactive' => 'wstecz po nowej regule',
        'source' => 'źródło zgłoszenia',
    ];

    /**
     * Plugin reports of the mailbox in the period: verdict => count.
     *
     * @return array<string,int>
     */
    public function pluginReports(string $email, ?\DateTimeImmutable $since): array
    {
        $sql = 'SELECT verdict, COUNT(*) AS cnt FROM antispam_plugin_report WHERE account_email = ?';
        $params = [$email];
        if ($since) {
            $sql .= ' AND reported_at >= ?';
            $params[] = $since->format('Y-m-d H:i:s');
        }
        $out = [];
        try {
            foreach ($this->db()->fetchAllAssociative($sql . ' GROUP BY verdict', $params) as $row) {
                $out[(string)$row['verdict']] = (int)$row['cnt'];
            }
        } catch (\Throwable) {
            // table missing on a very old schema
        }
        return $out;
    }
}
