<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AccountDailyStat;

/**
 * Variables of Account/stats.html.twig, shared by the admin page
 * (/account/stats/{id}) and the user's own one (/my/stats/{id}).
 */
class AccountStatsPage
{
    /** Periods: ?days= value => label (0 = everything recorded). */
    public const PERIODS = [1 => 'dziś', 7 => '7 dni', 30 => '30 dni', 90 => '90 dni', 365 => 'rok', 0 => 'od początku'];

    public function __construct(
        private AccountStatsService $stats,
        private SshService $ssh,
    ) {
    }

    public static function days(int $days): int
    {
        return array_key_exists($days, self::PERIODS) ? $days : 30;
    }

    /**
     * @param bool $agent SSH: also read the agent's own log (`stats`, agent 3.9+)
     * @param bool $admin raw agent errors (hosts, paths) only for admins
     */
    public function build(Account $account, int $days, bool $agent, bool $admin = true): array
    {
        $days = self::days($days);
        $since = AccountStatsService::since($days ?: null);
        $email = (string)$account->getEmail();

        $agentStats = null;
        if ($account->isSsh() && $agent) {
            try {
                $agentStats = $this->ssh->runStats($account, $days);
            } catch (\Throwable $e) {
                $agentStats = ['success' => false, 'error' => $e->getMessage()];
            }
            if (empty($agentStats['success']) || !isset($agentStats['decisions'])) {
                $error = (string)($agentStats['error'] ?? 'nieprawidłowa odpowiedź agenta') . (isset($agentStats['agent_warning']) ? ' ' . $agentStats['agent_warning'] : '');
                $agentStats = ['success' => false, 'error' => $admin ? $error
                    : (str_contains($error, 'nie obsługuje') ? 'Agent na serwerze tej skrzynki jest w starszej wersji - poproś administratora o jego aktualizację.' : 'Serwer skrzynki nie odpowiedział - spróbuj później.')];
            }
        }

        return [
            'account' => $account,
            'days' => $days,
            'periods' => self::PERIODS,
            'kinds' => AccountDailyStat::KINDS,
            'totals' => $this->stats->totals((int)$account->getId(), $since),
            'daily' => $this->stats->daily((int)$account->getId(), in_array($days, [0, 1, 7], true) ? 30 : min($days, 90)),
            'log' => $this->stats->scoreLog($email, $since),
            'plugin_reports' => $this->stats->pluginReports($email, $since),
            'agent' => $agentStats,
            'admin' => $admin,
            'stats_route' => $admin ? 'antispam_account_stats' : 'antispam_my_stats',
            'scorelog_route' => $admin ? 'antispam_spambox_scorelog' : 'antispam_my_scorelog',
            'own_accounts' => [],
        ];
    }
}
