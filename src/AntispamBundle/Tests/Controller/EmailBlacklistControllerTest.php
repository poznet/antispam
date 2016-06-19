<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class EmailBlacklistControllerTest extends WebTestCase
{

    public function testIndex()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/emailblacklst/index');
        $this->assertContains('E-mail Blacklists', $client->getResponse()->getContent());
    }

    public function testaddButton()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/emailblacklst/index');
        $this->assertContains('Dodaj', $client->getResponse()->getContent());
    }
}
