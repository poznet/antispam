<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/** "Spam w skrzynkach": mailbox list on the side, one mailbox, "Przywróć z domeny". */
class MySpamPageTest extends KernelTestCase
{
    public function testOneMailboxWithTheListAndDomainRelease()
    {
        self::bootKernel();
        $c = self::getContainer();
        $r = Request::create('/my/spam');
        $r->attributes->set('_route', 'antispam_my_spam');
        $r->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($r);
        $u = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($u, 'main', $u->getRoles()));
        $html = $c->get('twig')->render('@Antispam/My/spam.html.twig', ['limit' => 100, 'admin' => true, 'selected' => 'imap-6',
            'all_mailboxes' => [['key' => 'imap-5', 'label' => 'Jan'], ['key' => 'imap-6', 'label' => 'Ola']],
            'mailboxes' => [['key' => 'imap-6', 'label' => 'Ola', 'total' => 1, 'error' => null, 'items' => [
                ['id' => '3', 'from' => 'a@mail.firma.pl', 'from_name' => '', 'subject' => 's', 'date' => null, 'score' => 12, 'reasons' => [], 'labels' => [], 'high_risk' => false, 'uidvalidity' => 1, 'sender_domain' => 'firma.pl'],
            ]]]]);
        $this->assertStringContainsString('href="/my/spam?mailbox=imap-5"', $html);
        $this->assertMatchesRegularExpression('~list-group-item active"[^>]*>\s*<span[^>]*></span> Ola~', $html);
        $this->assertStringContainsString('action="/my/spam/domain"', $html);
        $this->assertStringContainsString('data-domain="*.firma.pl"', $html);
        $this->assertStringContainsString('Spam w skrzynkach', $html);
        $this->assertStringContainsString('href="/my/spam?mailbox=imap-6&amp;msg=3&amp;uidvalidity=1#podglad"', $html);
        $this->assertStringNotContainsString('Folder spamu', $html, 'old page gone from the menu');
    }

    public function testPreviewIsSandboxed()
    {
        self::bootKernel();
        $c = self::getContainer();
        $r = Request::create('/my/spam');
        $r->attributes->set('_route', 'antispam_my_spam');
        $r->setSession(new Session(new MockArraySessionStorage()));
        $c->get('request_stack')->push($r);
        $u = new InMemoryUser('admin', 'x', ['ROLE_ADMIN']);
        $c->get('security.token_storage')->setToken(new UsernamePasswordToken($u, 'main', $u->getRoles()));
        $html = $c->get('twig')->render('@Antispam/My/spam.html.twig', ['limit' => 100, 'admin' => true, 'selected' => 'imap-6',
            'all_mailboxes' => [['key' => 'imap-6', 'label' => 'Ola']],
            'preview' => ['success' => true, 'id' => '3', 'subject' => 'Oferta <b>', 'from' => 'a@ab.pl', 'date' => null, 'attachments' => ['faktura.pdf'], 'truncated' => false,
                'document' => \AntispamBundle\Controller\SpamboxController::previewDocument('<img src="https://track.test/p.gif"><script>x()</script>', null)],
            'mailboxes' => [['key' => 'imap-6', 'label' => 'Ola', 'total' => 0, 'error' => null, 'items' => []]]]);
        $this->assertMatchesRegularExpression('~<iframe sandbox="" referrerpolicy="no-referrer"~', $html);
        $this->assertStringContainsString('Oferta &lt;b&gt;', $html);
        $this->assertStringContainsString('faktura.pdf', $html);
        $this->assertStringNotContainsString('<script>x()', $html, 'message HTML only inside the escaped srcdoc');
        $this->assertStringContainsString('default-src', $html);
    }
}
