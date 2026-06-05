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
        $port = (int)($this->config->get('imap_port') ?: 993);
        $flags = $this->config->get('imap_flags') ?: '/imap/ssl';
        $server = new Server(
            $this->config->get('imap'),
            $port,
            $flags
        );
        $this->connection = $server->authenticate($this->config->get('login'), $this->config->get('password'));

    }

    /**
     * @return Server
     */
    public function getConnection()
    {
        return $this->connection;
    }





   
}