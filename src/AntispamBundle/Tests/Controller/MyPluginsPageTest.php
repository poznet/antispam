<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/** "Moja poczta → Wtyczki pocztowe" renders the downloads and the login hints. */
class MyPluginsPageTest extends KernelTestCase
{
    private function render(array $vars): string
    {
        self::bootKernel();
        $c = self::getContainer();
        $request = Request::create('/my/plugins');
        $request->attributes->set('_route', 'antispam_my_plugins');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($request);
        $user = new InMemoryUser('jan', 'x', ['ROLE_USER']);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($user, 'main', $user->getRoles()));
        return $c->get('twig')->render('@Antispam/My/plugins.html.twig', $vars + [
            'enabled' => true, 'server' => 'https://antispam.example.pl', 'version' => '1.7.0', 'outlook_ok' => true, 'mailboxes' => [],
        ]);
    }

    public function testDownloadsAndMailboxes()
    {
        $html = $this->render(['mailboxes' => [
            ['email' => 'jan@firma.pl', 'plugin_password' => true, 'imap_password' => false],
            ['email' => 'biuro@firma.pl', 'plugin_password' => false, 'imap_password' => false],
        ]]);
        $this->assertStringContainsString('/plugin/download?v=1.7.0', $html);
        $this->assertStringContainsString('/plugin/outlook/manifest.xml', $html);
        $this->assertStringContainsString('value="https://antispam.example.pl"', $html);
        $this->assertStringContainsString('jan@firma.pl', $html);
        $this->assertStringContainsString('hasło wtyczki ustawione', $html);
        $this->assertStringContainsString('poproś administratora o hasło wtyczki', $html);
        $this->assertStringContainsString('href="/my/plugins"', $html, 'nav entry');
    }

    public function testOutlookNeedsHttpsAndDisabledPlugins()
    {
        $this->assertStringContainsString('wymaga adresu https', $this->render(['outlook_ok' => false, 'server' => 'http://10.0.0.1']));
        $html = $this->render(['enabled' => false]);
        $this->assertStringContainsString('wyłączone przez administratora', $html);
        $this->assertStringNotContainsString('/plugin/download', $html);
    }
}
