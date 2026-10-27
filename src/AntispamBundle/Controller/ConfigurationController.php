<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Event\ConfigEvent;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UrlAnalyzer;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * @Route("/config")
 */
class ConfigurationController extends Controller
{
    /**
     * @Route("/email/", name="antispam_account_config")
     * @Template
     */
    public function emailConfigAction(Request $request)
    {
        if ($request->getMethod() == 'POST') {
            $this->get('configuration')->set('email', $request->get('config')['email']);
            $this->get('configuration')->set('password', $request->get('config')['password']);
            $this->get('configuration')->set('login', $request->get('config')['login']);
            $this->get('configuration')->set('imap', $request->get('config')['imap']);
            if (!array_key_exists('delete', $request->get('config'))) {
                $this->get('configuration')->set('delete', false);
            } else {
                $this->get('configuration')->set('delete', true);
            }
        }
        $config = [
            'email' => $this->get('configuration')->get('email'),
            'password' => $this->get('configuration')->get('password'),
            'login' => $this->get('configuration')->get('login'),
            'imap' => $this->get('configuration')->get('imap'),
            'delete' => $this->get('configuration')->get('delete'),
        ];
        return ['config' => $config];
    }

    /**
     * @Template
     * @Route("/spam/", name="antispam_spam_config")
     */
    public function spamConfigAction(Request $request)
    {
        $c = $this->get('configuration');
        if ($request->getMethod() == 'POST') {
            $post = $request->get('config', []);
            $c->set('delete', array_key_exists('delete', $post));
            $c->set('scoring.enabled', array_key_exists('scoring_enabled', $post));
            $c->set('scoring.dnsbl_enabled', array_key_exists('dnsbl_enabled', $post));
            $c->set('scoring.header_check_enabled', array_key_exists('header_check_enabled', $post));
            $c->set('scoring.log_enabled', array_key_exists('log_enabled', $post));
            $c->set('scoring.clamav_enabled', array_key_exists('clamav_enabled', $post));
            $c->set('scoring.clamav_dsn', trim($post['clamav_dsn'] ?? '') ?: ScoringService::DEFAULT_CLAMAV_DSN);
            $c->set('scoring.clamav_score', max(1, (int)($post['clamav_score'] ?? ScoringService::DEFAULT_CLAMAV_SCORE)));
            // Max attachment size is entered in MiB for readability, stored in bytes.
            $maxMib = max(1, (int)($post['clamav_max_size_mib'] ?? (ScoringService::DEFAULT_CLAMAV_MAX_SIZE / 1048576)));
            $c->set('scoring.clamav_max_size', $maxMib * 1048576);
            $c->set('scoring.clamav_timeout', max(1, (int)($post['clamav_timeout'] ?? ScoringService::DEFAULT_CLAMAV_TIMEOUT)));
            $c->set('scoring.vt_enabled', array_key_exists('vt_enabled', $post));
            $c->set('scoring.vt_api_key', trim($post['vt_api_key'] ?? ''));
            $c->set('scoring.vt_score', max(1, (int)($post['vt_score'] ?? ScoringService::DEFAULT_VT_SCORE)));
            $c->set('scoring.vt_threshold', max(1, (int)($post['vt_threshold'] ?? ScoringService::DEFAULT_VT_THRESHOLD)));
            $c->set('scoring.vt_timeout', max(1, (int)($post['vt_timeout'] ?? ScoringService::DEFAULT_VT_TIMEOUT)));
            $c->set('scoring.spam_threshold', max(1, (int)($post['spam_threshold'] ?? ScoringService::DEFAULT_SPAM_THRESHOLD)));
            $c->set('scoring.quarantine_threshold', max(0, (int)($post['quarantine_threshold'] ?? ScoringService::DEFAULT_QUARANTINE_THRESHOLD)));

            // Impersonation / BEC
            $scoring = $this->get('antispam.scoring');
            $c->set('impersonation.enabled', array_key_exists('impersonation_enabled', $post));
            $c->set('impersonation.protect_own_domain', array_key_exists('protect_own_domain', $post));
            foreach (ImpersonationAnalyzer::DEFAULT_SCORES as $k => $default) {
                $c->set('impersonation.' . $k . '_score', max(0, (int)($post['impersonation_' . $k . '_score'] ?? $default)));
            }
            $scoring->setListSetting(ScoringService::LIST_PROTECTED_DOMAINS, implode("\n", ImpersonationAnalyzer::parseDomains($post['protected_domains'] ?? '')));
            $scoring->setListSetting(ScoringService::LIST_VIPS, trim(str_replace("\r", '', $post['vips'] ?? '')));

            // Link protection
            $c->set('url.enabled', array_key_exists('url_enabled', $post));
            $c->set('url.dbl_enabled', array_key_exists('url_dbl_enabled', $post));
            foreach (['mismatch_score', 'ip_score', 'shortener_score', 'punycode_score', 'gsb_score'] as $k) {
                $c->set('url.' . $k, max(0, (int)($post['url_' . $k] ?? UrlAnalyzer::DEFAULT_CONFIG[$k])));
            }
            $c->set('url.max_domains', max(1, (int)($post['url_max_domains'] ?? UrlAnalyzer::DEFAULT_CONFIG['max_domains'])));
            $c->set('url.gsb_enabled', array_key_exists('url_gsb_enabled', $post));
            $c->set('url.gsb_api_key', trim($post['url_gsb_api_key'] ?? ''));
            $zones = UrlAnalyzer::parseZones($post['url_dbl_zones'] ?? '');
            $scoring->setListSetting(ScoringService::LIST_URL_DBL_ZONES, implode("\n", array_map(function ($z) {
                return $z['zone'] . ' ' . $z['score'];
            }, $zones)));

            // Attachment policy
            $c->set('attachment.policy_enabled', array_key_exists('attachment_policy_enabled', $post));
            foreach (AttachmentPolicyAnalyzer::DEFAULT_SCORES as $k => $default) {
                $c->set('attachment.' . $k, max(0, (int)($post['attachment_' . $k] ?? $default)));
            }
            $scoring->setListSetting(ScoringService::LIST_BLOCKED_EXTENSIONS, implode(', ', AttachmentPolicyAnalyzer::parseExtensions($post['blocked_extensions'] ?? '')));

            $this->addFlash('success', 'Settings saved');
        }

        $config = [
            'delete' => $c->get('delete'),
            'scoring_enabled' => $c->get('scoring.enabled'),
            'dnsbl_enabled' => $c->get('scoring.dnsbl_enabled'),
            'header_check_enabled' => $c->get('scoring.header_check_enabled'),
            'log_enabled' => $c->get('scoring.log_enabled'),
            'clamav_enabled' => $c->get('scoring.clamav_enabled'),
            'clamav_dsn' => $c->get('scoring.clamav_dsn') ?: ScoringService::DEFAULT_CLAMAV_DSN,
            'clamav_score' => $c->get('scoring.clamav_score') ?: ScoringService::DEFAULT_CLAMAV_SCORE,
            'clamav_max_size_mib' => (int)(($c->get('scoring.clamav_max_size') ?: ScoringService::DEFAULT_CLAMAV_MAX_SIZE) / 1048576),
            'clamav_timeout' => $c->get('scoring.clamav_timeout') ?: ScoringService::DEFAULT_CLAMAV_TIMEOUT,
            'vt_enabled' => $c->get('scoring.vt_enabled'),
            'vt_api_key' => $c->get('scoring.vt_api_key') ?: '',
            'vt_score' => $c->get('scoring.vt_score') ?: ScoringService::DEFAULT_VT_SCORE,
            'vt_threshold' => $c->get('scoring.vt_threshold') ?: ScoringService::DEFAULT_VT_THRESHOLD,
            'vt_timeout' => $c->get('scoring.vt_timeout') ?: ScoringService::DEFAULT_VT_TIMEOUT,
            'spam_threshold' => $c->get('scoring.spam_threshold') ?: ScoringService::DEFAULT_SPAM_THRESHOLD,
            'quarantine_threshold' => $c->get('scoring.quarantine_threshold') ?: ScoringService::DEFAULT_QUARANTINE_THRESHOLD,
        ];

        $scoring = $this->get('antispam.scoring');
        $url = $scoring->getUrlConfig();
        $config += [
            'impersonation_enabled' => $scoring->isImpersonationEnabled(),
            'protect_own_domain' => $scoring->isProtectOwnDomain(),
            'impersonation_scores' => $scoring->getImpersonationScores(),
            'protected_domains' => implode("\n", $scoring->getProtectedDomains()),
            'vips' => $scoring->getVipList(),
            'url_enabled' => $scoring->isUrlCheckEnabled(),
            'url' => $url,
            'url_dbl_zones' => $scoring->getUrlDblZonesText(),
            'attachment_policy_enabled' => $scoring->isAttachmentPolicyEnabled(),
            'attachment' => $scoring->getAttachmentPolicyConfig(),
            'blocked_extensions' => $scoring->getBlockedExtensionsText(),
        ];
        return ['config' => $config];
    }

    /**
     * End-user quarantine digest: e-mail with one-click release / whitelist /
     * delete links, sent by `antispam:digest:send` from cron.
     *
     * @Template
     * @Route("/digest/", name="antispam_digest_config")
     */
    public function digestConfigAction(Request $request)
    {
        $c = $this->get('configuration');
        $digest = $this->get('antispam.digest');

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('digest_config', $request->request->get('_token'))) {
                $this->addFlash('danger', 'Invalid form token, please try again.');
                return $this->redirectToRoute('antispam_digest_config');
            }
            $post = $request->get('config', []);
            $c->set('digest.enabled', array_key_exists('enabled', $post));
            $c->set('digest.base_url', rtrim(trim($post['base_url'] ?? ''), '/'));
            $c->set('digest.from_email', trim($post['from_email'] ?? ''));
            $c->set('digest.from_name', trim($post['from_name'] ?? ''));
            $c->set('digest.imap_recipient', trim($post['imap_recipient'] ?? ''));
            $c->set('digest.token_ttl_days', max(1, min(30, (int)($post['token_ttl_days'] ?? QuarantineDigestService::DEFAULT_TTL_DAYS))));
            $c->set('digest.max_items', max(1, min(500, (int)($post['max_items'] ?? QuarantineDigestService::DEFAULT_MAX_ITEMS))));

            if ($request->request->get('send_now')) {
                $errors = $digest->configurationErrors();
                if ($errors) {
                    $this->addFlash('danger', implode(' ', $errors));
                } else {
                    foreach ($digest->sendAll() as $row) {
                        $type = $row['status'] === 'error' || $row['status'] === 'rejected' ? 'danger' : 'info';
                        $this->addFlash($type, sprintf('%s → %s: %d message(s), %s%s', $row['key'], $row['recipient'], $row['count'], $row['status'], $row['error'] ? ' (' . $row['error'] . ')' : ''));
                    }
                }
            } else {
                $this->addFlash('success', 'Digest settings saved');
            }
            return $this->redirectToRoute('antispam_digest_config');
        }

        $mailboxes = [];
        try {
            $mailboxes = $this->get('antispam.quarantine')->getMailboxes();
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Could not list mailboxes: ' . $e->getMessage());
        }
        foreach ($mailboxes as &$m) {
            $m['last_sent'] = $digest->getLastSent($m['key']);
        }
        unset($m);

        return [
            'config' => [
                'enabled' => $digest->isEnabled(),
                'base_url' => $digest->getBaseUrl(),
                'from_email' => $digest->getFromEmail(),
                'from_name' => $c->get('digest.from_name') ?: '',
                'imap_recipient' => $c->get('digest.imap_recipient') ?: '',
                'token_ttl_days' => $digest->getTtlDays(),
                'max_items' => $digest->getMaxItems(),
            ],
            'errors' => $digest->configurationErrors(),
            'mailboxes' => $mailboxes,
        ];
    }

    /**
     * Render the digest a mailbox would receive (last 7 days), without sending.
     *
     * @Route("/digest/preview/{key}", name="antispam_digest_preview", requirements={"key"="imap|ssh-\d+"})
     */
    public function digestPreviewAction($key)
    {
        $digest = $this->get('antispam.digest');
        $mailbox = $this->get('antispam.quarantine')->getMailbox($key);
        if (!$mailbox) {
            throw $this->createNotFoundException('Unknown mailbox');
        }
        try {
            $html = $digest->renderHtml($digest->build($mailbox, new \DateTimeImmutable('-7 days')));
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Preview failed: ' . $e->getMessage());
            return $this->redirectToRoute('antispam_digest_config');
        }
        return new Response($html);
    }

    /**
     * Shared spam feed (centralized spam DB) settings: whether this instance
     * participates, the local API key (so other instances can push to us), and
     * the remote hub URL + key we sync against.
     *
     * @Template
     * @Route("/feed/", name="antispam_feed_config")
     */
    public function feedConfigAction(Request $request)
    {
        $c = $this->get('configuration');
        if ($request->getMethod() == 'POST') {
            $post = $request->get('config', []);
            $c->set('feed.enabled', array_key_exists('enabled', $post));
            $c->set('feed.score', max(1, (int)($post['score'] ?? 6)));
            $c->set('feed.min_reports', max(1, (int)($post['min_reports'] ?? 1)));
            $c->set('feed.server_key', trim($post['server_key'] ?? ''));
            $c->set('feed.remote_url', rtrim(trim($post['remote_url'] ?? ''), '/'));
            $c->set('feed.remote_key', trim($post['remote_key'] ?? ''));
            $this->addFlash('success', 'Shared feed settings saved');
            return $this->redirectToRoute('antispam_feed_config');
        }

        $config = [
            'enabled' => $c->get('feed.enabled'),
            'score' => $c->get('feed.score') ?: 6,
            'min_reports' => $c->get('feed.min_reports') ?: 1,
            'server_key' => $c->get('feed.server_key') ?: '',
            'remote_url' => $c->get('feed.remote_url') ?: '',
            'remote_key' => $c->get('feed.remote_key') ?: '',
            'last_pull_at' => $c->get('feed.last_pull_at') ?: null,
        ];

        $stats = $this->getDoctrine()->getManager()
            ->getRepository('AntispamBundle:SharedSpamSignal')->countByOrigin();

        return ['config' => $config, 'stats' => $stats];
    }

    /**
     * @Route("/uncheck-all/", name="antispam_spam_unchekall")
     */
    public function uncheckAllAction()
    {
        $this->get('antispam.message')->unCheckAll();
        return $this->redirectToRoute('antispam_spam_config');
    }

    /**
     * @Route("/spam/clamav-test/", name="antispam_clamav_test")
     */
    public function clamavTestAction()
    {
        $c = $this->get('configuration');
        $dsn = $c->get('scoring.clamav_dsn') ?: ScoringService::DEFAULT_CLAMAV_DSN;
        $timeout = $c->get('scoring.clamav_timeout') ?: ScoringService::DEFAULT_CLAMAV_TIMEOUT;

        if ($this->get('antispam.clamav')->ping($dsn, $timeout)) {
            $this->addFlash('success', sprintf('ClamAV daemon reachable at %s', $dsn));
        } else {
            $this->addFlash('danger', sprintf('Could not reach ClamAV daemon at %s — check that clamd is running and the address is correct.', $dsn));
        }

        return $this->redirectToRoute('antispam_spam_config');
    }

    /**
     * @Route("/spam/virustotal-test/", name="antispam_virustotal_test")
     */
    public function virusTotalTestAction()
    {
        $c = $this->get('configuration');
        $apiKey = trim((string)$c->get('scoring.vt_api_key'));
        $timeout = $c->get('scoring.vt_timeout') ?: ScoringService::DEFAULT_VT_TIMEOUT;

        if ($apiKey === '') {
            $this->addFlash('danger', 'No VirusTotal API key configured.');
        } elseif ($this->get('antispam.virustotal')->ping($apiKey, $timeout)) {
            $this->addFlash('success', 'VirusTotal API key is valid and reachable.');
        } else {
            $this->addFlash('danger', 'Could not reach VirusTotal or the API key was rejected.');
        }

        return $this->redirectToRoute('antispam_spam_config');
    }

    /**
     * @Route("/reset/countes/", name="antispam_spam_resetcounters")
     */
    public function resetCountersAction()
    {
        $dispatcher = $this->get('event_dispatcher');
        $dispatcher->dispatch('antispam.config.event', new ConfigEvent('resetcounters'));
        return $this->redirectToRoute('antispam_spam_config');
    }
}
