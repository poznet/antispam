<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 17.06.16
 * Time: 23:03
 */

namespace AntispamBundle\Services;

use Ddeboer\Imap\ConnectionInterface;
use Ddeboer\Imap\ServerFactory;
use Poznet\ConfigBundle\Service\ConfigService;

class ConnectionService
{
    private $config;
    private $connection;

    public function __construct(ConfigService $config)
    {
        $this->config = $config;

        $serverFactory = new ServerFactory();
        $server = $serverFactory->create(
            $this->config->get('imap'),
            143,
            '/novalidate-cert/notls'
        );

        $this->connection = $server->authenticate(
            $this->config->get('login'),
            $this->config->get('password')
        );
    }

    /**
     * @return ConnectionInterface
     */
    public function getConnection(): ConnectionInterface
    {
        return $this->connection;
    }
}
