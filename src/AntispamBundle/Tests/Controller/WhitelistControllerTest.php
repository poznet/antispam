<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class WhitelistControllerTest extends WebTestCase
{
    public function testIndex()
    {
        $client = static::createClient();

        $crawler = $client->request('GET', '/whitelit/');

        $this->assertContains('whitelist', $client->getResponse()->getContent());
    }
}
