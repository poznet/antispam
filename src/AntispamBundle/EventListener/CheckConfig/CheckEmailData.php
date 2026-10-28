<?php

namespace AntispamBundle\EventListener\CheckConfig;

use AntispamBundle\Event\CheckEvent;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\CryptoService;
use Ddeboer\Imap\Exception\AbstractException;
use Ddeboer\Imap\Server;

/**
 * Validates the IMAP settings from the "E-mail" settings page
 * (`antispam:check`).
 */
class CheckEmailData
{
    private $config;

    // CryptoService: the password is stored encrypted (legacy plain text passes through).
    public function __construct(ConfigService $config, private ?CryptoService $crypto = null)
    {
        $this->config = $config;
    }

    public function checkEmail(CheckEvent $event)
    {
        if (strlen(trim((string)$this->config->get('email'))) < 3) {
            $event->setStatus(false);
            $event->addMessage('Configuration : Wrong Email');
        }
    }

    public function checkLogin(CheckEvent $event)
    {
        if (strlen(trim((string)$this->config->get('login'))) < 2) {
            $event->setStatus(false);
            $event->addMessage('Configuration : Empty Login');
        }
    }

    public function checkPass(CheckEvent $event)
    {
        if (strlen(trim((string)$this->config->get('password'))) < 2) {
            $event->setStatus(false);
            $event->addMessage('Configuration : Empty Password');
        }
    }

    public function checkImap(CheckEvent $event)
    {
        if (strlen(trim((string)$this->config->get('imap'))) < 3) {
            $event->setStatus(false);
            $event->addMessage('Configuration : Empty Imap Server');
        }
    }

    /**
     * Tries to log in to the IMAP server (only when the settings look valid).
     */
    public function tryToConnect(CheckEvent $event)
    {
        if ($event->getStatus() !== true) {
            return;
        }
        $server = new Server((string)$this->config->get('imap'), (string)($this->config->get('imap_port') ?: '993'), (string)($this->config->get('imap_flags') ?: '/imap/ssl'));
        try {
            $password = (string)$this->config->get('password');
            $server->authenticate((string)$this->config->get('login'), (string)($this->crypto ? $this->crypto->decrypt($password) : $password));
        } catch (AbstractException $e) {
            $event->setStatus(false);
            $event->addMessage('Connection :  ' . $e->getMessage());
        }
    }
}
