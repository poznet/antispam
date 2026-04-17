<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Event\ConfigEvent;
use AntispamBundle\Services\ScoringService;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

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
            $c->set('scoring.spam_threshold', max(1, (int)($post['spam_threshold'] ?? ScoringService::DEFAULT_SPAM_THRESHOLD)));
            $c->set('scoring.quarantine_threshold', max(0, (int)($post['quarantine_threshold'] ?? ScoringService::DEFAULT_QUARANTINE_THRESHOLD)));
            $this->addFlash('success', 'Settings saved');
        }

        $config = [
            'delete' => $c->get('delete'),
            'scoring_enabled' => $c->get('scoring.enabled'),
            'dnsbl_enabled' => $c->get('scoring.dnsbl_enabled'),
            'header_check_enabled' => $c->get('scoring.header_check_enabled'),
            'log_enabled' => $c->get('scoring.log_enabled'),
            'spam_threshold' => $c->get('scoring.spam_threshold') ?: ScoringService::DEFAULT_SPAM_THRESHOLD,
            'quarantine_threshold' => $c->get('scoring.quarantine_threshold') ?: ScoringService::DEFAULT_QUARANTINE_THRESHOLD,
        ];
        return ['config' => $config];
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
     * @Route("/reset/countes/", name="antispam_spam_resetcounters")
     */
    public function resetCountersAction()
    {
        $dispatcher = $this->get('event_dispatcher');
        $dispatcher->dispatch('antispam.config.event', new ConfigEvent('resetcounters'));
        return $this->redirectToRoute('antispam_spam_config');
    }
}
