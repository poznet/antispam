<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/** Bayes section of Ustawienia → Filtr spamu. */
class BayesSettingsTemplateTest extends KernelTestCase
{
    private function render(array $bayes): string
    {
        self::bootKernel();
        $request = Request::create('/');
        $request->setSession(new Session(new MockArraySessionStorage()));
        self::getContainer()->get('request_stack')->push($request);
        $config = array_fill_keys(['attachment_policy_enabled', 'blocked_extensions', 'clamav_dsn', 'clamav_enabled', 'clamav_max_size_mib', 'clamav_score',
            'clamav_timeout', 'delete', 'dnsbl_enabled', 'header_check_enabled', 'impersonation_enabled', 'log_enabled', 'protect_own_domain',
            'protected_domains', 'quarantine_threshold', 'scoring_enabled', 'spam_threshold', 'url_dbl_zones', 'url_enabled', 'vips', 'vt_enabled',
            'vt_score', 'vt_threshold', 'vt_timeout'], '') + [
            'url' => ['gsb_api_key' => ['set' => false, 'hint' => '']] + \AntispamBundle\Services\UrlAnalyzer::DEFAULT_CONFIG,
            'attachment' => \AntispamBundle\Services\AttachmentPolicyAnalyzer::DEFAULT_SCORES,
            'impersonation_scores' => \AntispamBundle\Services\ImpersonationAnalyzer::DEFAULT_SCORES,
            'vt_api_key' => ['set' => false, 'hint' => ''],
        ];
        return self::getContainer()->get('twig')->render('@Antispam/Configuration/spamConfig.html.twig', ['config' => $config, 'bayes' => $bayes]);
    }

    public function testShowsSettingsStatsAndReset()
    {
        $html = $this->render(['enabled' => true, 'per_mailbox' => false, 'min_spam' => 50, 'min_ham' => 50, 'agent_max_tokens' => 20000,
            'spam_score' => 5, 'likely_score' => 3, 'ham_score' => 2,
            'stats' => ['spam' => 12, 'ham' => 40, 'tokens' => 1234, 'tokens_all' => 1234, 'scopes' => 0, 'messages' => 52, 'ready' => false, 'min_spam' => 50, 'min_ham' => 50]]);
        $this->assertStringContainsString('Klasyfikator uczący się (Bayes)', $html);
        $this->assertMatchesRegularExpression('~name="config\[bayes_enabled\]"\s+checked~', $html);
        $this->assertStringContainsString('<strong>12</strong> spam, <strong>40</strong> nie-spam', $html);
        $this->assertStringContainsString('za mało przykładów (min. 50 / 50)', $html);
        $this->assertStringContainsString('/config/spam/bayes-reset/', $html);
    }

    public function testMissingTablesHint()
    {
        $html = $this->render(['enabled' => false, 'per_mailbox' => false, 'min_spam' => 50, 'min_ham' => 50, 'agent_max_tokens' => 0,
            'spam_score' => 5, 'likely_score' => 3, 'ham_score' => 2, 'stats' => null]);
        $this->assertStringContainsString('antispam:db:upgrade', $html);
    }
}
