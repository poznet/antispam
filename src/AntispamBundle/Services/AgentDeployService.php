<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;

class AgentDeployService
{
    private $ssh;

    public function __construct(SshService $ssh)
    {
        $this->ssh = $ssh;
    }

    public function deploy(Account $account)
    {
        $agentSource = __DIR__ . '/../Resources/agent/antispam-agent.php';
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';

        $this->ssh->upload($account, $agentSource, $remotePath);

        $output = $this->ssh->exec($account, "php {$remotePath} test 2>&1");
        return json_decode($output, true) ?: ['success' => false, 'error' => $output];
    }

    public function getRemoteAgentVersion(Account $account)
    {
        $remotePath = $account->getAgentPath() . '/antispam-agent.php';
        $output = $this->ssh->exec($account, "php {$remotePath} version 2>&1");
        $result = json_decode($output, true);
        return $result['version'] ?? null;
    }

    public function getLocalAgentVersion()
    {
        $agentSource = __DIR__ . '/../Resources/agent/antispam-agent.php';
        if (!file_exists($agentSource)) {
            return null;
        }
        $content = file_get_contents($agentSource);
        if (preg_match("/define\('AGENT_VERSION',\s*'([^']+)'\)/", $content, $m)) {
            return $m[1];
        }
        return null;
    }

    public function needsUpdate(Account $account)
    {
        $local = $this->getLocalAgentVersion();
        $remote = $this->getRemoteAgentVersion($account);
        if (!$local || !$remote) {
            return true;
        }
        return version_compare($remote, $local, '<');
    }
}
