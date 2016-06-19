<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 19.06.16
 * Time: 18:16
 */

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;


class DomainBlacklistControllerTest extends WebTestCase
{

    public function testIndex()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/domainblacklst/index');
        $this->assertContains('Domain Blacklist', $client->getResponse()->getContent());
    }

    public function testaddButton()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/domainblacklst/index');
        $this->assertContains('Dodaj', $client->getResponse()->getContent());
    }
}