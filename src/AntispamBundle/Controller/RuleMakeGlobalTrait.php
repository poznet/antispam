<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\RuleGlobalizer;
use AntispamBundle\Services\RuleOwnership;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * "Zmień na: Wszystkie skrzynki" on the admin rule lists (domain / e-mail
 * white- and blacklists): one rule, the checked rules (`ids[]`) or every rule
 * of one mailbox (`all_of=<owner>`). The work - duplicate merge, audit,
 * retroactive pass, SSH agent sync - is RuleGlobalizer::makeGlobal().
 *
 * Admin only: the lists live under the ROLE_ADMIN part of access_control and
 * the actions carry #[IsGranted('ROLE_ADMIN')]; the user area (/my/rules)
 * never creates global rules (UserRulePolicy).
 *
 * The using controller provides $em, $globalizer (?RuleGlobalizer) and checkToken().
 */
trait RuleMakeGlobalTrait
{
    /** POST /{list}/global/{id} */
    protected function makeGlobalOne(Request $request, int|string $id, string $type, string $indexRoute): RedirectResponse
    {
        $this->checkToken($request);
        $rule = $this->em->getRepository(RuleGlobalizer::LISTS[$type][0])->find((int)$id);
        if ($rule === null) {
            $this->addFlash('warning', 'Nie ma takiej reguły - mogła zostać usunięta.');
            return $this->backToList($request, $indexRoute);
        }
        if (RuleOwnership::isGlobal($rule->getEmail())) {
            $this->addFlash('info', 'Ta reguła już dotyczy wszystkich skrzynek.');
            return $this->backToList($request, $indexRoute);
        }
        return $this->runMakeGlobal([$rule], $request, $indexRoute);
    }

    /** POST /{list}/global with ids[] (checked rules) or all_of=<owner> (every rule of that mailbox). */
    protected function makeGlobalBulk(Request $request, string $type, string $indexRoute): RedirectResponse
    {
        $this->checkToken($request);
        $repo = $this->em->getRepository(RuleGlobalizer::LISTS[$type][0]);
        $allOf = trim((string)$request->request->get('all_of', ''));
        if ($allOf !== '') {
            if (RuleOwnership::isGlobal($allOf)) {
                $this->addFlash('info', 'Reguły globalne już dotyczą wszystkich skrzynek.');
                return $this->backToList($request, $indexRoute);
            }
            $rules = $repo->findBy(['email' => $allOf], ['id' => 'ASC']);
        } else {
            $ids = $request->request->all('ids');
            $ids = array_values(array_unique(array_filter(array_map('intval', is_array($ids) ? $ids : []), fn($id) => $id > 0)));
            $rules = $ids ? $repo->findBy(['id' => $ids], ['id' => 'ASC']) : [];
        }
        $rules = array_values(array_filter($rules, fn($rule) => !RuleOwnership::isGlobal($rule->getEmail())));
        if (!$rules) {
            $this->addFlash('info', 'Nie zaznaczono żadnej reguły przypisanej do pojedynczej skrzynki - nic nie zmieniono.');
            return $this->backToList($request, $indexRoute);
        }
        return $this->runMakeGlobal($rules, $request, $indexRoute);
    }

    private function runMakeGlobal(array $rules, Request $request, string $indexRoute): RedirectResponse
    {
        if ($this->globalizer === null) {
            throw new \LogicException('RuleGlobalizer is not wired into ' . static::class);
        }
        $result = $this->globalizer->makeGlobal($rules);

        $parts = [];
        if ($result['moved'] > 0) {
            $parts[] = sprintf('zmieniono na „Wszystkie skrzynki”: %d', $result['moved']);
        }
        if ($result['merged'] > 0) {
            $parts[] = sprintf('scalono z istniejącą regułą globalną (licznik trafień dodany, kopia skrzynki usunięta): %d', $result['merged']);
        }
        $this->addFlash('success', 'Reguły - ' . implode('; ', $parts) . '. Działają teraz dla każdej skrzynki.');
        if ($result['retroactive']) {
            $this->addFlash('info', sprintf('Poczta, która już jest w skrzynkach (ostatnie 30 dni, wszystkie konta), zostanie sprawdzona pod kątem %s w tle - %s (Przegląd → Zadania w tle).',
                count($result['retroactive']) === 1 ? 'tej reguły' : 'tych reguł',
                implode(', ', array_map(fn($q) => '#' . $q->id, $result['retroactive']))));
        }
        if ($result['synced'] > 0) {
            $this->addFlash('info', sprintf('Reguły zostaną wysłane do agentów SSH w tle (kont: %d).', $result['synced']));
        }
        return $this->backToList($request, $indexRoute);
    }

    /** Back to the list, keeping the owner filter the form was submitted from. */
    private function backToList(Request $request, string $indexRoute): RedirectResponse
    {
        // After "every rule of this mailbox" that filter is empty - show the global rules.
        $owner = trim((string)$request->request->get('all_of', '')) !== '' ? RuleOwnership::ALL : trim((string)$request->request->get('return_owner', ''));
        return $this->redirectToRoute($indexRoute, $owner !== '' ? ['owner' => $owner] : []);
    }
}
