<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\BulkImportController;
use AntispamBundle\Controller\DomainBlacklistController;
use AntispamBundle\Controller\EmailWhitelistController;
use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\Jobs\EnqueueResult;
use AntispamBundle\Tests\Support\RuleFixtures;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ServiceLocator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * Panel rule forms: the owner comes from the mailbox selector (validated),
 * dedupe is per owner, an install without the legacy mailbox can still add
 * rules (global), and bulk import is CSRF-protected.
 */
class RuleListControllersTest extends TestCase
{
    private Session $session;

    private function wire(AbstractController $controller, string $validTokenId = 'list_rules'): void
    {
        $csrf = $this->createMock(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturnCallback(
            fn(CsrfToken $t) => $t->getId() === $validTokenId && $t->getValue() === 'good'
        );
        $router = $this->createMock(RouterInterface::class);
        $router->method('generate')->willReturnCallback(fn($name) => '/' . $name);
        $this->session = new Session(new MockArraySessionStorage());
        $request = new Request();
        $request->setSession($this->session);
        $stack = new RequestStack();
        $stack->push($request);

        $controller->setContainer(new ServiceLocator([
            'security.csrf.token_manager' => fn() => $csrf,
            'router' => fn() => $router,
            'request_stack' => fn() => $stack,
        ]));
    }

    private function post(array $data): Request
    {
        return Request::create('/x', 'POST', $data);
    }

    private function bulk(RuleFixtures $db): BulkImportController
    {
        $controller = new BulkImportController($db->em, $db->ownership());
        $this->wire($controller, BulkImportController::CSRF_ID);
        return $controller;
    }

    public function testBulkImportRejectsMissingOrWrongCsrfToken()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $controller = $this->bulk($db);

        foreach ([[], ['_token' => 'bad'], ['_token' => 'good-but-other-id']] as $token) {
            try {
                $controller->importAction($this->post($token + ['entries' => "spam.example"]), 'blacklist');
                $this->fail('import without a valid CSRF token must be refused');
            } catch (AccessDeniedException) {
            }
        }
        $this->assertSame([], $db->persisted);
        $this->assertSame(0, $db->flushes);
    }

    public function testBulkImportTokenFromAnotherFormIsRefused()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $controller = new BulkImportController($db->em, $db->ownership());
        $this->wire($controller, 'list_rules'); // only the list_rules token is "valid"

        $this->expectException(AccessDeniedException::class);
        $controller->importAction($this->post(['_token' => 'good', 'entries' => 'spam.example']), 'blacklist');
    }

    public function testBulkImportStoresChosenOwnerAndDedupesPerOwner()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl', 'anna@firma.pl']);
        $db->add((new Blacklist())->setEmail('jan@firma.pl')->setHost('old.example'));
        $db->add((new Blacklist())->setEmail('*')->setHost('global.example'));

        $this->bulk($db)->importAction($this->post([
            '_token' => 'good',
            'owner' => 'anna@firma.pl',
            'pattern_type' => 'exact',
            'score' => '7',
            'entries' => "old.example\nglobal.example\nNew.example\nnew.example\n# comment",
        ]), 'blacklist');

        $hosts = array_map(fn($r) => $r->getEmail() . '|' . $r->getHost() . '|' . $r->getScore(), $db->persisted);
        // old.example belongs to jan only -> allowed for anna; global.example already covers anna.
        $this->assertSame(['anna@firma.pl|old.example|7', 'anna@firma.pl|new.example|7'], $hosts);
    }

    public function testBulkImportRejectsUnknownOwner()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl');
        $this->bulk($db)->importAction($this->post([
            '_token' => 'good', 'owner' => 'obcy@example.com', 'entries' => 'spam.example',
        ]), 'email_blacklist');

        $this->assertSame([], $db->persisted);
        $this->assertNotEmpty($this->session->getFlashBag()->get('danger'));
    }

    public function testBulkImportWithoutLegacyMailboxCreatesGlobalRules()
    {
        $db = new RuleFixtures($this, null);
        $this->bulk($db)->importAction($this->post(['_token' => 'good', 'entries' => 'x@spam.example']), 'email_blacklist');

        $this->assertCount(1, $db->persisted);
        $this->assertInstanceOf(EmailBlacklist::class, $db->persisted[0]);
        $this->assertSame('*', $db->persisted[0]->getEmail());
    }

    public function testParseEntriesRoundTripsTheExportFormat()
    {
        $export = "# Blacklista domen - eksport\nspam.example\texact\t10\tjan@firma.pl\n^mail\\d+\\.Spam$\tregex\t25\t*\n*.evil.example\twildcard\t5\t*\n";
        $this->assertSame([
            ['value' => 'spam.example', 'pattern_type' => 'exact', 'score' => 10],
            ['value' => '^mail\\d+\\.Spam$', 'pattern_type' => 'regex', 'score' => 25],
            ['value' => '*.evil.example', 'pattern_type' => 'wildcard', 'score' => 5],
        ], BulkImportController::parseEntries($export, 'exact', 10));
    }

    public function testParseEntriesKeepsRegexVerbatim()
    {
        $this->assertSame(
            [['value' => '^[A-Z]{2,5}\\D$', 'pattern_type' => 'regex', 'score' => 3]],
            BulkImportController::parseEntries('^[A-Z]{2,5}\\D$', 'regex', 3)
        );
        $this->assertSame(
            ['a.example', 'b.example', 'c.example'],
            array_column(BulkImportController::parseEntries("A.example, b.example; c.example", 'exact', 1), 'value')
        );
    }

    public function testPanelAddWithoutLegacyMailboxStoresGlobalRule()
    {
        $db = new RuleFixtures($this, null, ['jan@firma.pl']);
        $retro = $this->createMock(DeferredRetroactivePass::class);
        // The pass over mail already in INBOX is queued, never run in the request.
        $retro->expects($this->once())->method('queue')->with($this->isInstanceOf(Blacklist::class))->willReturn(new EnqueueResult(7, true));
        $controller = new DomainBlacklistController($db->em, $db->ownership(), $retro);
        $this->wire($controller);

        $controller->addAction($this->post(['_token' => 'good', 'host' => 'spam.example', 'score' => '10']));

        $this->assertCount(1, $db->persisted);
        $this->assertSame('*', $db->persisted[0]->getEmail(), 'no legacy mailbox: NOT NULL column gets the global owner, not null');
        $this->assertStringContainsString('zadanie #7', $this->session->getFlashBag()->get('info')[0]);
    }

    public function testPanelAddUsesSelectedMailboxAndDedupesPerOwner()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl']);
        $controller = new EmailWhitelistController($db->em, $db->ownership());
        $this->wire($controller);

        $controller->addAction($this->post(['_token' => 'good', 'email' => 'friend@x.pl', 'owner' => 'jan@firma.pl']));
        $controller->addAction($this->post(['_token' => 'good', 'email' => 'friend@x.pl', 'owner' => 'jan@firma.pl']));
        $controller->addAction($this->post(['_token' => 'good', 'email' => 'friend@x.pl', 'owner' => 'biuro@firma.pl']));
        $controller->addAction($this->post(['_token' => 'good', 'email' => 'friend@x.pl', 'owner' => 'obcy@x.pl']));

        $owners = array_map(fn(EmailWhitelist $r) => $r->getEmail(), $db->persisted);
        $this->assertSame(['jan@firma.pl', 'biuro@firma.pl'], $owners);
    }

    public function testPanelAddWithoutOwnerFieldKeepsLegacyBehaviour()
    {
        $db = new RuleFixtures($this, 'biuro@firma.pl', ['jan@firma.pl']);
        $controller = new EmailWhitelistController($db->em, $db->ownership());
        $this->wire($controller);

        $controller->addAction($this->post(['_token' => 'good', 'email' => 'friend@x.pl']));
        $this->assertSame('biuro@firma.pl', $db->persisted[0]->getEmail());
    }
}
