<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Account;
use AntispamBundle\Security\MailboxAccess;
use AntispamBundle\Services\DeferredAgentSync;
use AntispamBundle\Services\RuleOwnership;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\UserRulePolicy;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Own white/blacklists of an end user (/my/rules): sender address and domain
 * rules owned by one of the user's mailboxes - never '*' (global rules are
 * admin-only) - exact and wildcard only (UserRulePolicy).
 *
 * Ownership is checked server-side on every write: the owner of a new rule
 * must be one of MailboxAccess::accountEmails(), and a rule is only deleted
 * when its stored owner is one of them (no IDOR through the id). Changes of
 * SSH mailboxes reach the agent through DeferredAgentSync (a background job).
 *
 * A new blacklist rule is NOT applied retroactively to mail already in INBOX
 * (unlike the admin forms): see docs/users.md.
 */
#[Route('/my/rules')]
class MyRulesController extends AbstractController
{
    use AuditTrait;

    /** Per mailbox and list. */
    public const MAX_RULES = 500;
    /** Points of a user blacklist rule: at least the spam threshold, so it is decisive. */
    public const MIN_BLACKLIST_SCORE = 10;
    private const CSRF = 'my_rules';

    public function __construct(
        private EntityManagerInterface $em,
        private MailboxAccess $access,
        private RuleOwnership $ownership,
        private DeferredAgentSync $agentSync,
        private ScoringService $scoring,
    ) {
    }

    #[Route('', name: 'antispam_my_rules', methods: ['GET'])]
    public function indexAction(): Response
    {
        $owners = $this->owners();
        $lists = [];
        foreach (UserRulePolicy::LISTS as $key => [$class, $field]) {
            $rules = $owners ? $this->em->getRepository($class)->findBy(['email' => $owners], ['id' => 'ASC']) : [];
            $lists[$key] = [
                'label' => UserRulePolicy::LABELS[$key],
                'field' => $field,
                // Defence in depth: never show a rule whose owner is not one of the user's mailboxes.
                'rules' => array_values(array_filter($rules, fn($r) => $this->ownerOf($owners, (string)$r->getEmail()) !== null)),
            ];
        }
        return $this->render('@Antispam/My/rules.html.twig', [
            'lists' => $lists,
            'owners' => $owners,
            'ssh_owners' => $this->sshOwners($owners),
        ]);
    }

    #[Route('/add', name: 'antispam_my_rules_add', methods: ['POST'])]
    public function addAction(Request $request): Response
    {
        $this->checkToken($request);
        $list = (string)$request->request->get('list');
        if (!isset(UserRulePolicy::LISTS[$list])) {
            $this->addFlash('danger', 'Nieznana lista.');
            return $this->redirectToRoute('antispam_my_rules');
        }
        [$class, $field, , $isBlacklist] = UserRulePolicy::LISTS[$list];

        $owners = $this->owners();
        $owner = $this->ownerOf($owners, (string)$request->request->get('owner'));
        if ($owner === null) {
            // Foreign mailbox, '*' or garbage: refused, never "corrected".
            throw $this->createAccessDeniedException();
        }

        $type = (string)$request->request->get('pattern_type', 'exact');
        $value = UserRulePolicy::normalize($list, (string)$request->request->get('value'));
        if ($error = UserRulePolicy::validate($list, $value, $type)) {
            $this->addFlash('danger', $error);
            return $this->redirectToRoute('antispam_my_rules');
        }
        if ($this->ownership->findDuplicate($class, $field, $owner, $value)) {
            $this->addFlash('info', 'Ta reguła już istnieje dla tej skrzynki (lub dla wszystkich skrzynek).');
            return $this->redirectToRoute('antispam_my_rules');
        }
        if (count($this->em->getRepository($class)->findBy(['email' => $owner])) >= self::MAX_RULES) {
            $this->addFlash('danger', sprintf('Osiągnięto limit %d reguł na tej liście dla skrzynki %s.', self::MAX_RULES, $owner));
            return $this->redirectToRoute('antispam_my_rules');
        }

        $rule = new $class();
        $rule->setEmail($owner);
        $rule->{'set' . ucfirst($field)}($value);
        $rule->setPatternType($type);
        $details = ['pattern_type' => $type, 'source' => 'my'];
        if ($isBlacklist) {
            $rule->setScore(max(self::MIN_BLACKLIST_SCORE, (int)$this->scoring->getSpamThreshold()));
            $details['score'] = $rule->getScore();
        }
        $this->em->persist($rule);
        $this->em->flush();
        $this->audit('rule.add', targetType: $list, targetId: $rule->getId(), label: $value, mailbox: $owner, details: $details);

        $this->addFlash('success', sprintf('Dodano regułę „%s” (%s) dla skrzynki %s.', $value, UserRulePolicy::LABELS[$list], $owner)
            . ($isBlacklist ? ' Dotyczy nowych wiadomości - poczta, która już jest w skrzynce, nie jest przenoszona.' : ''));
        $this->scheduleSync($owner);
        return $this->redirectToRoute('antispam_my_rules');
    }

    #[Route('/delete', name: 'antispam_my_rules_delete', methods: ['POST'])]
    public function deleteAction(Request $request): Response
    {
        $this->checkToken($request);
        $list = (string)$request->request->get('list');
        if (!isset(UserRulePolicy::LISTS[$list])) {
            $this->addFlash('danger', 'Nieznana lista.');
            return $this->redirectToRoute('antispam_my_rules');
        }
        [$class, $field] = UserRulePolicy::LISTS[$list];

        $rule = $this->em->getRepository($class)->find((int)$request->request->get('id'));
        if (!$rule) {
            $this->addFlash('info', 'Nie znaleziono reguły (została już usunięta?).');
            return $this->redirectToRoute('antispam_my_rules');
        }
        // Global ('*') and foreign rules look the same to the user: forbidden.
        $owner = $this->ownerOf($this->owners(), (string)$rule->getEmail());
        if ($owner === null) {
            throw $this->createAccessDeniedException();
        }

        $id = $rule->getId();
        $value = (string)$rule->{'get' . ucfirst($field)}();
        $this->em->remove($rule);
        $this->em->flush();
        $this->audit('rule.delete', targetType: $list, targetId: $id, label: $value, mailbox: $owner, details: ['pattern_type' => $rule->getPatternType(), 'source' => 'my']);

        $this->addFlash('success', sprintf('Usunięto regułę „%s”.', $value));
        $this->scheduleSync($owner);
        return $this->redirectToRoute('antispam_my_rules');
    }

    /**
     * Rule owners the current user may manage: the e-mails of the assigned
     * accounts; for an administrator every account e-mail. Never '*'.
     *
     * @return string[]
     */
    private function owners(): array
    {
        $emails = $this->access->accountEmails($this->getUser());
        if ($emails === null) {
            $emails = [];
            foreach ($this->em->getRepository(Account::class)->findBy([], ['email' => 'ASC']) as $account) {
                $email = trim((string)$account->getEmail());
                if ($email !== '') {
                    $emails[strtolower($email)] = $email;
                }
            }
            $emails = array_values($emails);
        }
        return array_values(array_filter($emails, fn($e) => $e !== '' && !RuleOwnership::isGlobal($e)));
    }

    /** The canonical owner from $owners matching $requested (case-insensitive), or null. */
    private function ownerOf(array $owners, string $requested): ?string
    {
        $requested = trim($requested);
        if ($requested === '' || RuleOwnership::isGlobal($requested)) {
            return null;
        }
        foreach ($owners as $owner) {
            if (strcasecmp($owner, $requested) === 0) {
                return $owner;
            }
        }
        return null;
    }

    /** @return string[] owners that are SSH+Maildir mailboxes (rules need an agent sync) */
    private function sshOwners(array $owners): array
    {
        if (!$owners) {
            return [];
        }
        $out = [];
        foreach ($this->em->getRepository(Account::class)->findBy(['email' => $owners, 'connectionType' => Account::CONNECTION_SSH]) as $account) {
            $out[] = strtolower((string)$account->getEmail());
        }
        return array_values(array_unique($out));
    }

    private function scheduleSync(string $owner): void
    {
        if ($this->agentSync->deferForOwner($owner) > 0) {
            $this->addFlash('info', 'Skrzynka działa przez agenta na serwerze: zmiana zostanie do niego wysłana w ciągu kilkunastu sekund i od tej chwili będzie stosowana przy skanowaniu.');
        }
    }

    private function checkToken(Request $request): void
    {
        if (!$this->isCsrfTokenValid(self::CSRF, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
    }
}
