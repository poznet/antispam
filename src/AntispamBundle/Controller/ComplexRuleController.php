<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\ComplexRule;
use AntispamBundle\Services\ComplexRuleEngine;
use AntispamBundle\Services\ComplexRuleService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\RuleOwnership;
use AntispamBundle\Services\SenderIntelService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * "Reguły złożone" (docs/complex-rules.md): AND / OR condition trees per
 * mailbox or for every mailbox - created here or in the Thunderbird plugin
 * (source "plugin"), applied on the server (IMAP pipeline, plugin checks,
 * SSH agent).
 */
#[Route('/complex-rules')]
#[IsGranted('ROLE_ADMIN')]
class ComplexRuleController extends AbstractController
{
    use AuditTrait;

    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
        private ComplexRuleService $complex,
        private ConfigService $config,
        private SenderIntelService $intel,
        private ?DeferredAgentSync $agentSync = null,
    ) {
    }

    #[Route('', name: 'antispam_complex_rule_index', methods: ['GET'])]
    #[Template('@Antispam/ComplexRule/index.html.twig')]
    public function indexAction(Request $request)
    {
        $all = $this->em->getRepository(ComplexRule::class)->findBy([], ['id' => 'ASC']);
        $owner = (string)$request->query->get('owner', '');
        return [
            'list' => RuleOwnership::filterByOwner($all, $owner),
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'owner_filter' => $owner,
            'lookups' => $this->intel->isEnabled(),
            'test' => null,
            'test_owner' => $this->ownership->defaultOwner(),
        ];
    }

    #[Route('/new', name: 'antispam_complex_rule_new', methods: ['GET', 'POST'])]
    public function newAction(Request $request)
    {
        $rule = (new ComplexRule())->setEmail($this->ownership->defaultOwner())->setSource(ComplexRule::SOURCE_PANEL);
        return $this->form($request, $rule, true);
    }

    #[Route('/{id}/edit', name: 'antispam_complex_rule_edit', requirements: ['id' => '\d+'], methods: ['GET', 'POST'])]
    public function editAction($id, Request $request)
    {
        $rule = $this->em->getRepository(ComplexRule::class)->find($id);
        if (!$rule) {
            throw $this->createNotFoundException();
        }
        return $this->form($request, $rule, false);
    }

    private function form(Request $request, ComplexRule $rule, bool $new)
    {
        $errors = [];
        if ($request->isMethod('POST')) {
            $this->checkToken($request);
            $owner = $this->ownership->resolve($request->request->get('owner'));
            $data = [
                'name' => $request->request->get('name'),
                'action' => $request->request->get('action'),
                'score' => $request->request->get('score'),
                'enabled' => $request->request->has('enabled'),
                'conditions' => (string)$request->request->get('conditions'),
            ];
            if ($owner === null) {
                $errors[] = 'Nieznana skrzynka - wybierz skrzynkę z listy.';
            } elseif ($new || $owner !== $rule->getEmail()) {
                if ($this->em->getRepository(ComplexRule::class)->countOwnedBy($owner) >= ComplexRuleService::MAX_PER_OWNER) {
                    $errors[] = 'Ta skrzynka ma już ' . ComplexRuleService::MAX_PER_OWNER . ' reguł złożonych.';
                }
            }
            $oldOwner = $rule->getEmail();
            if (!$errors) {
                $errors = $this->complex->apply($rule, $data);
            }
            if (!$errors) {
                $rule->setEmail($owner);
                if ($new) {
                    $rule->setCreatedBy('admin:' . ($this->getUser()?->getUserIdentifier() ?? ''));
                    $this->em->persist($rule);
                }
                $this->em->flush();
                $this->changed($rule, $new ? 'rule.add' : 'rule.update', $new ? null : $oldOwner);
                $this->addFlash('success', ($new ? 'Dodano' : 'Zapisano') . ' regułę złożoną „' . $rule->getName() . '”.');
                return $this->redirectToRoute('antispam_complex_rule_index');
            }
            if (!$new) {
                $this->em->refresh($rule);
            }
            // Keep what was typed in the form.
            $posted = json_decode($data['conditions'], true);
            return $this->render('@Antispam/ComplexRule/form.html.twig', $this->formVars($rule, $new, $errors, [
                'name' => (string)$data['name'], 'action' => (string)$data['action'], 'score' => (string)$data['score'],
                'enabled' => $data['enabled'], 'owner' => (string)$request->request->get('owner'),
                'conditions' => is_array($posted) ? $posted : $rule->getConditionTree(),
            ]));
        }
        return $this->render('@Antispam/ComplexRule/form.html.twig', $this->formVars($rule, $new, [], [
            'name' => $rule->getName(), 'action' => $rule->getAction(), 'score' => (string)$rule->getScore(),
            'enabled' => $rule->isEnabled(), 'owner' => $rule->getEmail(),
            'conditions' => $new ? ['op' => 'and', 'items' => [['field' => 'subject', 'match' => 'contains', 'value' => '']]] : $rule->getConditionTree(),
        ]));
    }

    private function formVars(ComplexRule $rule, bool $new, array $errors, array $values): array
    {
        return [
            'rule' => $rule,
            'new' => $new,
            'errors' => $errors,
            'values' => $values,
            'choices' => $this->ownership->choices(),
            'actions' => ComplexRuleEngine::ACTIONS,
            'vocab' => ComplexRuleService::vocabulary(),
        ];
    }

    #[Route('/{id}/delete', name: 'antispam_complex_rule_delete', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function deleteAction($id, Request $request)
    {
        $this->checkToken($request);
        $rule = $this->em->getRepository(ComplexRule::class)->find($id);
        if ($rule) {
            $snapshot = clone $rule;
            $this->em->remove($rule);
            $this->em->flush();
            $this->changed($snapshot, 'rule.delete', null, (int)$id);
            $this->addFlash('success', 'Usunięto regułę złożoną „' . $snapshot->getName() . '”.');
        }
        return $this->redirectToRoute('antispam_complex_rule_index', ['owner' => $request->request->get('return_owner', '')]);
    }

    #[Route('/{id}/toggle', name: 'antispam_complex_rule_toggle', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function toggleAction($id, Request $request)
    {
        $this->checkToken($request);
        $rule = $this->em->getRepository(ComplexRule::class)->find($id);
        if ($rule) {
            $rule->setEnabled(!$rule->isEnabled())->touch();
            $this->em->flush();
            $this->changed($rule, 'rule.update');
        }
        return $this->redirectToRoute('antispam_complex_rule_index', ['owner' => $request->request->get('return_owner', '')]);
    }

    /** Sender lookups (MX, domain age) on / off - complex.lookups. */
    #[Route('/lookups', name: 'antispam_complex_rule_lookups', methods: ['POST'])]
    public function lookupsAction(Request $request)
    {
        $this->checkToken($request);
        $on = $request->request->has('lookups');
        $this->config->set('complex.lookups', $on ? '1' : '0');
        $this->audit('settings.save', targetType: 'settings', targetId: 'complex.lookups', label: 'Reguły złożone: zapytania DNS / WHOIS', details: ['lookups' => $on]);
        $this->addFlash('success', $on ? 'Zapytania o MX i wiek domeny włączone.' : 'Zapytania o MX i wiek domeny wyłączone - takie warunki nie będą pasować.');
        return $this->redirectToRoute('antispam_complex_rule_index');
    }

    /**
     * "Testuj na wiadomości": the pasted source against every rule of a
     * mailbox (disabled ones too), without counting hits or touching mail.
     */
    #[Route('/test', name: 'antispam_complex_rule_test', methods: ['POST'])]
    #[Template('@Antispam/ComplexRule/index.html.twig')]
    public function testAction(Request $request)
    {
        $this->checkToken($request);
        $owner = $this->ownership->resolve($request->request->get('owner')) ?? RuleOwnership::ALL;
        $raw = str_replace(["\r\n", "\r"], "\n", (string)$request->request->get('raw'));
        $raw = str_replace("\n", "\r\n", substr($raw, 0, 4 * 1024 * 1024));
        $results = [];
        $fields = [];
        if (trim($raw) !== '') {
            $msg = $this->complex->messageFromRaw($raw, RuleOwnership::isGlobal($owner) ? null : $owner);
            foreach (ComplexRuleEngine::FIELDS as $key => $label) {
                if ($key !== 'header' && $key !== 'body') {
                    $fields[$label] = implode(', ', array_map(fn ($v) => mb_substr($v, 0, 200), $msg->values($key)));
                }
            }
            foreach ($this->em->getRepository(ComplexRule::class)->forMailbox($owner, false) as $rule) {
                $results[] = ['rule' => $rule, 'match' => ComplexRuleEngine::evaluate($rule->getConditionTree(), $msg->provider())];
            }
        }
        $all = $this->em->getRepository(ComplexRule::class)->findBy([], ['id' => 'ASC']);
        return [
            'list' => $all,
            'owners' => $this->ownership->labelsFor($all),
            'choices' => $this->ownership->choices(),
            'owner_filter' => '',
            'lookups' => $this->intel->isEnabled(),
            'test' => ['results' => $results, 'fields' => $fields, 'empty' => trim($raw) === ''],
            'test_owner' => $owner,
        ];
    }

    private function changed(ComplexRule $rule, string $action, ?string $oldOwner = null, ?int $id = null): void
    {
        $this->audit($action, targetType: 'complex_rule', targetId: $id ?? $rule->getId(), label: $rule->getName(), mailbox: $rule->getEmail(),
            details: ['action' => $rule->getAction(), 'score' => $rule->getScore(), 'enabled' => $rule->isEnabled(), 'conditions' => $rule->describe()]);
        $this->complex->clearRuntimeCache();
        if (!$this->agentSync) {
            return;
        }
        foreach (array_unique(array_filter([$rule->getEmail(), $oldOwner])) as $owner) {
            RuleOwnership::isGlobal($owner) ? $this->agentSync->deferAll('zmiana reguły złożonej') : $this->agentSync->deferForOwner($owner);
        }
    }

    private function checkToken(Request $request): void
    {
        if (!$this->isCsrfTokenValid('complex_rules', (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
