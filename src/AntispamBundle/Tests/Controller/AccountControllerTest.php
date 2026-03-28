<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class AccountControllerTest extends WebTestCase
{
    public function testIndexPage()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/account/index');

        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertContains('Accounts', $client->getResponse()->getContent());
    }

    public function testAddPageLoads()
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/account/add');

        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertContains('Add Account', $client->getResponse()->getContent());
        // CSRF token should be present
        $this->assertContains('_token', $client->getResponse()->getContent());
    }

    public function testDownloadAgent()
    {
        $client = static::createClient();
        $client->request('GET', '/account/download-agent');

        $this->assertEquals(200, $client->getResponse()->getStatusCode());
        $this->assertContains('attachment', $client->getResponse()->headers->get('Content-Disposition'));
    }

    public function testDeleteRequiresPostMethod()
    {
        $client = static::createClient();
        // GET should not work for delete (it's POST-only now)
        $client->request('GET', '/account/del/999');

        // Should return 405 Method Not Allowed
        $this->assertNotEquals(200, $client->getResponse()->getStatusCode());
    }
}
