<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:03
 */

namespace AntispamBundle\Services;

use Ddeboer\Imap\Server;
use Poznet\ConfigBundle\Service\ConfigService;

class ConnectionService
{
    private  $config;
    private  $connection;

    public function __construct(ConfigService $config)
    {
        $this->config=$config;
    }

    /**
     * Connects on first use, so pages that only need folder names still work
     * while the legacy IMAP account is not configured.
     *
     * @return \Ddeboer\Imap\ConnectionInterface
     */
    public function getConnection()
    {
        if (null === $this->connection) {
            $server = new Server(
                (string)$this->config->get('imap'),
                143,
                '/novalidate-cert/notls'
            );
            $this->connection = $server->authenticate((string)$this->config->get('login'), (string)$this->config->get('password'));
        }

        return $this->connection;
    }





   
}