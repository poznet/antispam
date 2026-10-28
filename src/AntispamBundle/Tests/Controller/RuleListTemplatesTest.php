<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;

/** The rule list pages render the mailbox selector, the owner filter and the owner of every rule. */
class RuleListTemplatesTest extends KernelTestCase
{
    public static function lists(): array
    {
        return [
            ['@Antispam/DomainBlacklist/index.html.twig', 'antispam_blacklist_index', (new Blacklist())->setHost('spam.example')],
            ['@Antispam/Whitelist/index.html.twig', 'antispam_whitelist_index', (new Whitelist())->setHost('ok.example')],
            ['@Antispam/EmailBlacklist/index.html.twig', 'antispam_emailblacklist_index', (new EmailBlacklist())->setBlacklistemail('a@spam.example')],
            ['@Antispam/EmailWhitelist/index.html.twig', 'antispam_emailwhitelist_index', (new EmailWhitelist())->setWhitelistemail('a@ok.example')],
        ];
    }

    private function render(string $template, array $vars): string
    {
        self::bootKernel();
        $request = Request::create('/');
        $request->setSession(new Session(new MockArraySessionStorage()));
        self::getContainer()->get('request_stack')->push($request);
        return self::getContainer()->get('twig')->render($template, $vars);
    }

    #[DataProvider('lists')]
    public function testListShowsOwners(string $template, string $route, object $rule)
    {
        $id = new \ReflectionProperty($rule, 'id');
        $global = clone $rule;
        $global->setEmail('*');
        $id->setValue($global, 1);
        $own = clone $rule;
        $own->setEmail('jan@firma.pl');
        $id->setValue($own, 2);

        $html = $this->render($template, [
            'list' => [$global, $own],
            'owners' => ['*' => 'Wszystkie skrzynki', 'jan@firma.pl' => 'jan@firma.pl'],
            'choices' => ['*' => 'Wszystkie skrzynki', 'jan@firma.pl' => 'jan@firma.pl'],
            'default_owner' => 'jan@firma.pl',
            'owner_filter' => '',
        ]);

        $this->assertStringContainsString('<select name="owner" id="rule-owner"', $html);
        $this->assertMatchesRegularExpression('~<option value="jan@firma.pl" selected>~', $html);
        $this->assertStringContainsString('id="owner-filter"', $html);
        $this->assertStringContainsString('label-primary" title="Reguła dotyczy wszystkich skrzynek">Wszystkie skrzynki', $html);
        $this->assertStringContainsString('label-info" title="Reguła dotyczy tylko tej skrzynki">jan@firma.pl', $html);
    }

    public function testBulkImportFormsCarryCsrfTokenAndOwner()
    {
        $html = $this->render('@Antispam/BulkImport/index.html.twig', [
            'types' => \AntispamBundle\Controller\BulkImportController::TYPES,
            'choices' => ['*' => 'Wszystkie skrzynki'],
            'default_owner' => '*',
        ]);
        $this->assertSame(4, substr_count($html, 'name="_token"'));
        $this->assertSame(4, substr_count($html, '<select name="owner"'));
    }
}
