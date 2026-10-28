<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\Server;

/**
 * IMAP connection for the mailbox configured on the "E-mail" settings page.
 * Connects on first use, so services depending on it can be built even when
 * IMAP is not configured or the server is down.
 */
class ConnectionService
{
    private $config;
    private $connection;

    // CryptoService: the password is stored encrypted (legacy plain text passes through).
    public function __construct(ConfigService $config, private ?CryptoService $crypto = null)
    {
        $this->config = $config;
    }

    /**
     * @return ConnectionInterface
     */
    public function getConnection()
    {
        if ($this->connection === null) {
            $server = new Server((string)$this->config->get('imap'), (string)($this->config->get('imap_port') ?: '993'), (string)($this->config->get('imap_flags') ?: '/imap/ssl'));
            $this->connection = $server->authenticate((string)$this->config->get('login'), (string)($this->crypto ? $this->crypto->decrypt((string)$this->config->get('password')) : $this->config->get('password')));
        }

        return $this->connection;
    }
}
