<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\ImapFlags;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\MailClientPluginBuilder;
use AntispamBundle\Services\MessageService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\QuarantineDigestService;
use AntispamBundle\Services\QuarantineService;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UrlAnalyzer;
use AntispamBundle\Services\VirusTotalService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/config')]
class ConfigurationController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
        private ScoringService $scoring,
        private QuarantineDigestService $digest,
        private QuarantineService $quarantine,
        private PluginService $plugin,
        private MessageService $messages,
        private ClamavService $clamav,
        private VirusTotalService $virusTotal,
    ) {
    }

    #[Route('/email/', name: 'antispam_account_config')]
    #[Template('@Antispam/Configuration/emailConfig.html.twig')]
    public function emailConfigAction(Request $request)
    {
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('email_config', (string)$request->request->get('_token'))) {
                throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
            }
            $post = $request->request->all('config');
            foreach (['email', 'password', 'login', 'imap', 'imap_port'] as $key) {
                $this->config->set($key, $post[$key] ?? '');
            }
            $this->config->set('imap_flags', ImapFlags::fromFormData($post));
            $this->config->set('delete', array_key_exists('delete', $post));
        }
        $config = [
            'email' => $this->config->get('email'),
            'password' => $this->config->get('password'),
            'login' => $this->config->get('login'),
            'imap' => $this->config->get('imap'),
            'imap_port' => $this->config->get('imap_port') ?: '993',
            'imap_flags' => $this->config->get('imap_flags') ?: '/imap/ssl',
            'delete' => $this->config->get('delete'),
        ];
        return ['config' => $config, 'imap_tls' => ImapFlags::parse($config['imap_flags'])];
    }

    #[Route('/spam/', name: 'antispam_spam_config')]
    #[Template('@Antispam/Configuration/spamConfig.html.twig')]
    public function spamConfigAction(Request $request)
    {
        $c = $this->config;
        if ($request->getMethod() == 'POST') {
            $post = $request->request->all('config');
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
                $c->set('impersonation.enabled', array_key_exists('impersonation_enabled', $post));
            $c->set('impersonation.protect_own_domain', array_key_exists('protect_own_domain', $post));
            foreach (ImpersonationAnalyzer::DEFAULT_SCORES as $k => $default) {
                $c->set('impersonation.' . $k . '_score', max(0, (int)($post['impersonation_' . $k . '_score'] ?? $default)));
            }
            $this->scoring->setListSetting(ScoringService::LIST_PROTECTED_DOMAINS, implode("\n", ImpersonationAnalyzer::parseDomains($post['protected_domains'] ?? '')));
            $this->scoring->setListSetting(ScoringService::LIST_VIPS, trim(str_replace("\r", '', $post['vips'] ?? '')));

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
            $this->scoring->setListSetting(ScoringService::LIST_URL_DBL_ZONES, implode("\n", array_map(function ($z) {
                return $z['zone'] . ' ' . $z['score'];
            }, $zones)));

            // Attachment policy
            $c->set('attachment.policy_enabled', array_key_exists('attachment_policy_enabled', $post));
            foreach (AttachmentPolicyAnalyzer::DEFAULT_SCORES as $k => $default) {
                $c->set('attachment.' . $k, max(0, (int)($post['attachment_' . $k] ?? $default)));
            }
            $this->scoring->setListSetting(ScoringService::LIST_BLOCKED_EXTENSIONS, implode(', ', AttachmentPolicyAnalyzer::parseExtensions($post['blocked_extensions'] ?? '')));

            $this->addFlash('success', 'Ustawienia zapisane');
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

        $url = $this->scoring->getUrlConfig();
        $config += [
            'impersonation_enabled' => $this->scoring->isImpersonationEnabled(),
            'protect_own_domain' => $this->scoring->isProtectOwnDomain(),
            'impersonation_scores' => $this->scoring->getImpersonationScores(),
            'protected_domains' => implode("\n", $this->scoring->getProtectedDomains()),
            'vips' => $this->scoring->getVipList(),
            'url_enabled' => $this->scoring->isUrlCheckEnabled(),
            'url' => $url,
            'url_dbl_zones' => $this->scoring->getUrlDblZonesText(),
            'attachment_policy_enabled' => $this->scoring->isAttachmentPolicyEnabled(),
            'attachment' => $this->scoring->getAttachmentPolicyConfig(),
            'blocked_extensions' => $this->scoring->getBlockedExtensionsText(),
        ];
        return ['config' => $config];
    }

    /**
     * End-user quarantine digest: e-mail with one-click release / whitelist /
     * delete links, sent by `antispam:digest:send` from cron.
     */
    #[Route('/digest/', name: 'antispam_digest_config')]
    #[Template('@Antispam/Configuration/digestConfig.html.twig')]
    public function digestConfigAction(Request $request)
    {
        $c = $this->config;

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('digest_config', $request->request->get('_token'))) {
                $this->addFlash('danger', 'Nieprawidłowy token formularza, spróbuj ponownie.');
                return $this->redirectToRoute('antispam_digest_config');
            }
            $post = $request->request->all('config');
            $c->set('digest.enabled', array_key_exists('enabled', $post));
            $c->set('digest.base_url', rtrim(trim($post['base_url'] ?? ''), '/'));
            $c->set('digest.from_email', trim($post['from_email'] ?? ''));
            $c->set('digest.from_name', trim($post['from_name'] ?? ''));
            $c->set('digest.imap_recipient', trim($post['imap_recipient'] ?? ''));
            $c->set('digest.token_ttl_days', max(1, min(30, (int)($post['token_ttl_days'] ?? QuarantineDigestService::DEFAULT_TTL_DAYS))));
            $c->set('digest.max_items', max(1, min(500, (int)($post['max_items'] ?? QuarantineDigestService::DEFAULT_MAX_ITEMS))));

            if ($request->request->get('send_now')) {
                $errors = $this->digest->configurationErrors();
                if ($errors) {
                    $this->addFlash('danger', implode(' ', $errors));
                } else {
                    foreach ($this->digest->sendAll() as $row) {
                        $type = $row['status'] === 'error' || $row['status'] === 'rejected' ? 'danger' : 'info';
                        $this->addFlash($type, sprintf('%s → %s: wiadomości: %d, status: %s%s', $row['key'], $row['recipient'], $row['count'], $row['status'], $row['error'] ? ' (' . $row['error'] . ')' : ''));
                    }
                }
            } else {
                $this->addFlash('success', 'Ustawienia raportu kwarantanny zapisane');
            }
            return $this->redirectToRoute('antispam_digest_config');
        }

        $mailboxes = [];
        try {
            $mailboxes = $this->quarantine->getMailboxes();
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Nie udało się pobrać listy skrzynek: ' . $e->getMessage());
        }
        foreach ($mailboxes as &$m) {
            $m['last_sent'] = $this->digest->getLastSent($m['key']);
        }
        unset($m);

        return [
            'config' => [
                'enabled' => $this->digest->isEnabled(),
                'base_url' => $this->digest->getBaseUrl(),
                'from_email' => $this->digest->getFromEmail(),
                'from_name' => $c->get('digest.from_name') ?: '',
                'imap_recipient' => $c->get('digest.imap_recipient') ?: '',
                'token_ttl_days' => $this->digest->getTtlDays(),
                'max_items' => $this->digest->getMaxItems(),
            ],
            'errors' => $this->digest->configurationErrors(),
            'mailboxes' => $mailboxes,
        ];
    }

    /** Render the digest a mailbox would receive (last 7 days), without sending. */
    #[Route('/digest/preview/{key}', name: 'antispam_digest_preview', requirements: ['key' => 'imap(-\d+)?|ssh-\d+'])]
    public function digestPreviewAction($key)
    {
        $mailbox = $this->quarantine->getMailbox($key);
        if (!$mailbox) {
            throw $this->createNotFoundException('Nieznana skrzynka');
        }
        try {
            $html = $this->digest->renderHtml($this->digest->build($mailbox, new \DateTimeImmutable('-7 days')));
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Podgląd nie powiódł się: ' . $e->getMessage());
            return $this->redirectToRoute('antispam_digest_config');
        }
        return new Response($html);
    }

    /**
     * Shared spam feed (centralized spam DB) settings: whether this instance
     * participates, the local API key (so other instances can push to us), and
     * the remote hub URL + key we sync against.
     */
    #[Route('/feed/', name: 'antispam_feed_config')]
    #[Template('@Antispam/Configuration/feedConfig.html.twig')]
    public function feedConfigAction(Request $request)
    {
        $c = $this->config;
        if ($request->getMethod() == 'POST') {
            $post = $request->request->all('config');
            $c->set('feed.enabled', array_key_exists('enabled', $post));
            $c->set('feed.score', max(1, (int)($post['score'] ?? 6)));
            $c->set('feed.min_reports', max(1, (int)($post['min_reports'] ?? 1)));
            $c->set('feed.server_key', trim($post['server_key'] ?? ''));
            $c->set('feed.remote_url', rtrim(trim($post['remote_url'] ?? ''), '/'));
            $c->set('feed.remote_key', trim($post['remote_key'] ?? ''));
            $this->addFlash('success', 'Ustawienia wspólnej bazy spamu zapisane');
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

        $stats = $this->em
            ->getRepository(SharedSpamSignal::class)->countByOrigin();

        return ['config' => $config, 'stats' => $stats];
    }

    /**
     * Mail client plugin settings (Thunderbird, Outlook, Apple Mail): download
     * links, anonymous reporting, on-arrival checks for logged-in users and
     * rule learning.
     */
    #[Route('/plugin/', name: 'antispam_plugin_config')]
    #[Template('@Antispam/Configuration/pluginConfig.html.twig')]
    public function pluginConfigAction(Request $request)
    {
        $c = $this->config;
        if ($request->getMethod() == 'POST') {
            $post = $request->request->all('config');
            // Stored as '1'/'0' so an unchecked box is not mistaken for "unset" (default on).
            foreach (['enabled', 'anonymous_reports', 'check_enabled', 'learn_rules'] as $flag) {
                $c->set('plugin.' . $flag, array_key_exists($flag, $post) ? '1' : '0');
            }
            $c->set('plugin.token_ttl_days', max(1, (int)($post['token_ttl_days'] ?? 90)));
            $c->set('plugin.report_rate_limit', max(1, (int)($post['report_rate_limit'] ?? 120)));
            $c->set('plugin.max_upload_kb', max(PluginService::MIN_MAX_UPLOAD_KB, min(10240, (int)($post['max_upload_kb'] ?? PluginService::DEFAULT_MAX_UPLOAD_KB))));
            // Baked into downloaded plugins (manifest XML, Swift source) - accept a plain http(s) base URL only.
            $publicUrl = rtrim(trim($post['public_url'] ?? ''), '/');
            $parts = $publicUrl !== '' ? parse_url($publicUrl) : null;
            if ($publicUrl !== '' && (!$parts || !in_array($parts['scheme'] ?? '', ['http', 'https'], true) || empty($parts['host'])
                || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
                || preg_match('/[\x00-\x20"\\\\<>]/', $publicUrl))) {
                $this->addFlash('danger', 'Nieprawidłowy publiczny adres URL - podaj np. https://antispam.example.pl');
                return $this->redirectToRoute('antispam_plugin_config');
            }
            $c->set('plugin.public_url', $publicUrl);
            $this->addFlash('success', 'Ustawienia wtyczek pocztowych zapisane');
            return $this->redirectToRoute('antispam_plugin_config');
        }

        $config = [
            'enabled' => $this->plugin->isEnabled(),
            'anonymous_reports' => $this->plugin->isAnonymousReportEnabled(),
            'check_enabled' => $this->plugin->isCheckEnabled(),
            'learn_rules' => $this->plugin->isLearnRulesEnabled(),
            'token_ttl_days' => $this->plugin->getTokenTtlDays(),
            'report_rate_limit' => $this->plugin->getReportRateLimit(),
            'max_upload_kb' => intdiv($this->plugin->getMaxUploadBytes(), 1024),
            'public_url' => $this->plugin->getPublicUrl(),
        ];
        $baseUrl = $this->plugin->getPublicUrl() ?: $request->getSchemeAndHttpHost() . $request->getBasePath();

        return [
            'config' => $config,
            'base_url' => $baseUrl,
            'outlook_ok' => MailClientPluginBuilder::isOutlookCompatible($baseUrl),
        ];
    }

    #[Route('/uncheck-all/', name: 'antispam_spam_unchekall')]
    public function uncheckAllAction()
    {
        $this->messages->unCheckAll();
        return $this->redirectToRoute('antispam_spam_config');
    }

    #[Route('/spam/clamav-test/', name: 'antispam_clamav_test')]
    public function clamavTestAction()
    {
        $c = $this->config;
        $dsn = $c->get('scoring.clamav_dsn') ?: ScoringService::DEFAULT_CLAMAV_DSN;
        $timeout = $c->get('scoring.clamav_timeout') ?: ScoringService::DEFAULT_CLAMAV_TIMEOUT;

        if ($this->clamav->ping($dsn, $timeout)) {
            $this->addFlash('success', sprintf('Demon ClamAV odpowiada pod adresem %s', $dsn));
        } else {
            $this->addFlash('danger', sprintf('Brak połączenia z demonem ClamAV pod adresem %s — sprawdź, czy clamd działa i czy adres jest poprawny.', $dsn));
        }

        return $this->redirectToRoute('antispam_spam_config');
    }

    #[Route('/spam/virustotal-test/', name: 'antispam_virustotal_test')]
    public function virusTotalTestAction()
    {
        $c = $this->config;
        $apiKey = trim((string)$c->get('scoring.vt_api_key'));
        $timeout = $c->get('scoring.vt_timeout') ?: ScoringService::DEFAULT_VT_TIMEOUT;

        if ($apiKey === '') {
            $this->addFlash('danger', 'Nie skonfigurowano klucza API VirusTotal.');
        } elseif ($this->virusTotal->ping($apiKey, $timeout)) {
            $this->addFlash('success', 'Klucz API VirusTotal jest poprawny, usługa odpowiada.');
        } else {
            $this->addFlash('danger', 'Brak połączenia z VirusTotal lub klucz API został odrzucony.');
        }

        return $this->redirectToRoute('antispam_spam_config');
    }

    #[Route('/reset/countes/', name: 'antispam_spam_resetcounters')]
    public function resetCountersAction()
    {
        foreach ([Blacklist::class, Whitelist::class, EmailBlacklist::class, EmailWhitelist::class] as $entity) {
            $this->em->createQuery('UPDATE ' . $entity . ' r SET r.counter = 0')->execute();
        }
        return $this->redirectToRoute('antispam_spam_config');
    }
}
