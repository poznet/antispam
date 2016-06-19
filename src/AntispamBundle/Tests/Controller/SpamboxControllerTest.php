<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class SpamboxControllerTest extends WebTestCase
{

    public function testTitle()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/spambox/index');
        $this->assertContains('Spambox', $client->getResponse()->getContent());
    }
}
