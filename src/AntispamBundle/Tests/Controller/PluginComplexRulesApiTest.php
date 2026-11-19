<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\PluginApiController;
use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\ComplexRule;
use AntispamBundle\Repository\ComplexRuleRepository;
use AntispamBundle\Services\ComplexRuleService;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\PhishingReportService;
use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\RawMessageScanner;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/** /api/plugin/complex-rules: who may create / edit what (docs/complex-rules.md). */
class PluginComplexRulesApiTest extends TestCase
{
    private const COND = ['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'contains', 'value' => 'faktura']]];

    private array $rules = [];
    private array $persisted = [];
    private array $removed = [];
    private bool $global = false;
    private bool $enabled = true;
    private $sync;

    private function rule(int $id, string $owner, ?string $createdBy = null): ComplexRule
    {
        $r = (new ComplexRule())->setEmail($owner)->setName('R' . $id)->setAction('spam')->setScore(10)->setConditionTree(self::COND)->setCreatedBy($createdBy);
        (new \ReflectionProperty(ComplexRule::class, 'id'))->setValue($r, $id);
        return $this->rules[$id] = $r;
    }

    private function controller(?Account $account = null): PluginApiController
    {
        $account ??= (new Account())->setEmail('jan@firma.pl');
        (new \ReflectionProperty(Account::class, 'id'))->setValue($account, 5);
        $plugin = $this->createMock(PluginService::class);
        $plugin->method('isEnabled')->willReturn(true);
        $plugin->method('isComplexRulesEnabled')->willReturnCallback(fn () => $this->enabled);
        $plugin->method('isGlobalComplexRulesEnabled')->willReturnCallback(fn () => $this->enabled && $this->global);
        $plugin->method('accountForToken')->willReturnCallback(fn ($t) => $t === 'T' ? $account : null);
        $plugin->method('hit')->willReturn(true);

        $repo = $this->createMock(ComplexRuleRepository::class);
        $repo->method('find')->willReturnCallback(fn ($id) => $this->rules[$id] ?? null);
        $repo->method('forMailbox')->willReturnCallback(fn ($m) => array_values(array_filter($this->rules, fn ($r) => in_array($r->getEmail(), [$m, '*'], true))));
        $repo->method('countOwnedBy')->willReturn(0);
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($repo);
        $em->method('persist')->willReturnCallback(function ($e) { $this->persisted[] = $e; });
        $em->method('remove')->willReturnCallback(function ($e) { $this->removed[] = $e; });
        $this->sync = $this->createMock(DeferredAgentSync::class);

        return new PluginApiController($this->createMock(RawMessageScanner::class), $plugin, $this->createMock(DeferredRetroactivePass::class),
            $em, $this->createMock(PhishingReportService::class), null, null, null, null, new ComplexRuleService($em), $this->sync);
    }

    private function req(string $method, array $body = [], string $token = 'T'): Request
    {
        $r = Request::create('/api/plugin/complex-rules', $method, [], [], [], [], $body ? json_encode($body) : null);
        $r->headers->set('Authorization', 'Bearer ' . $token);
        return $r;
    }

    public function testLoginAndSwitch()
    {
        $this->assertSame(401, $this->controller()->complexRulesAction($this->req('GET', [], 'bad'))->getStatusCode());
        $this->enabled = false;
        $this->assertSame(403, $this->controller()->complexRulesAction($this->req('GET'))->getStatusCode());
    }

    public function testCreateLocalRule()
    {
        $c = $this->controller();
        $this->sync->expects($this->once())->method('deferForOwner')->with('jan@firma.pl');
        $res = $c->complexRuleCreateAction($this->req('POST', ['name' => 'Faktury', 'action' => 'quarantine', 'conditions' => self::COND]));
        $this->assertSame(201, $res->getStatusCode());
        $rule = $this->persisted[0];
        $this->assertSame('jan@firma.pl', $rule->getEmail());
        $this->assertSame('plugin', $rule->getSource());
        $this->assertSame('plugin:jan@firma.pl', $rule->getCreatedBy());
        $this->assertSame(5, $rule->getScore());
    }

    public function testGlobalNeedsTheAdminSwitch()
    {
        $res = $this->controller()->complexRuleCreateAction($this->req('POST', ['action' => 'spam', 'conditions' => self::COND, 'global' => true]));
        $this->assertSame(403, $res->getStatusCode());
        $this->assertSame([], $this->persisted);

        $this->global = true;
        $c = $this->controller();
        $this->sync->expects($this->once())->method('deferAll');
        $this->assertSame(201, $c->complexRuleCreateAction($this->req('POST', ['action' => 'spam', 'conditions' => self::COND, 'global' => true]))->getStatusCode());
        $this->assertSame('*', $this->persisted[0]->getEmail());
    }

    public function testInvalidConditionsAre400()
    {
        $res = $this->controller()->complexRuleCreateAction($this->req('POST', ['action' => 'spam', 'conditions' => ['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'regex', 'value' => '(a']]]]));
        $this->assertSame(400, $res->getStatusCode());
    }

    public function testWhoMayEdit()
    {
        $this->rule(1, 'jan@firma.pl');
        $this->rule(2, '*', 'admin:root');
        $this->rule(3, '*', 'plugin:jan@firma.pl');
        $this->rule(4, 'anna@firma.pl');
        $c = $this->controller();

        $list = json_decode($c->complexRulesAction($this->req('GET'))->getContent(), true);
        $editable = array_column($list['rules'], 'editable', 'id');
        $this->assertSame([1 => true, 2 => false, 3 => false], $editable, 'global rules of the plugin only while global plugin rules are on');

        $this->assertSame(200, $c->complexRuleUpdateAction(1, $this->req('PUT', ['enabled' => false]))->getStatusCode());
        $this->assertFalse($this->rules[1]->isEnabled());
        $this->assertSame(403, $c->complexRuleUpdateAction(2, $this->req('PUT', ['enabled' => false]))->getStatusCode());
        $this->assertSame(404, $c->complexRuleUpdateAction(4, $this->req('PUT', ['enabled' => false]))->getStatusCode(), 'another mailbox: not even visible');
        $this->assertSame(404, $c->complexRuleDeleteAction(4, $this->req('DELETE'))->getStatusCode());
        $this->assertSame(403, $c->complexRuleUpdateAction(1, $this->req('PUT', ['global' => true]))->getStatusCode(), 'cannot move to global without the switch');

        $this->global = true;
        $c = $this->controller();
        $this->assertSame(200, $c->complexRuleUpdateAction(3, $this->req('PUT', ['score' => 7]))->getStatusCode());
        $this->assertSame(403, $c->complexRuleDeleteAction(2, $this->req('DELETE'))->getStatusCode(), 'admin global rule stays admin-only');
        $this->assertSame(200, $c->complexRuleDeleteAction(1, $this->req('DELETE'))->getStatusCode());
        $this->assertSame([$this->rules[1]], $this->removed);
    }
}
