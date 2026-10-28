<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/** Bulk import/export for all four rule lists. */
#[Route('/bulk')]
class BulkImportController extends AbstractController
{
    use AuditTrait;

    public const CSRF_ID = 'bulk_import';
    private const PATTERN_TYPES = ['exact', 'wildcard', 'regex'];

    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
    ) {
    }

    const TYPES = [
        'blacklist'       => ['entity' => Blacklist::class,      'field' => 'host',           'label' => 'Blacklista domen'],
        'whitelist'       => ['entity' => Whitelist::class,      'field' => 'host',           'label' => 'Whitelista domen'],
        'email_blacklist' => ['entity' => EmailBlacklist::class, 'field' => 'blacklistemail', 'label' => 'Blacklista adresów e-mail'],
        'email_whitelist' => ['entity' => EmailWhitelist::class, 'field' => 'whitelistemail', 'label' => 'Whitelista adresów e-mail'],
    ];

    #[Route('/', name: 'antispam_bulk_index')]
    #[Template('@Antispam/BulkImport/index.html.twig')]
    public function indexAction()
    {
        return [
            'types' => self::TYPES,
            'choices' => $this->ownership->choices(),
            'default_owner' => $this->ownership->defaultOwner(),
        ];
    }

    #[Route('/import/{type}', name: 'antispam_bulk_import', methods: ['POST'])]
    public function importAction(Request $request, $type)
    {
        if (!$this->isCsrfTokenValid(self::CSRF_ID, (string)$request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Nieprawidłowy token CSRF');
        }
        if (!isset(self::TYPES[$type])) {
            $this->addFlash('danger', 'Nieznany typ listy');
            return $this->redirectToRoute('antispam_bulk_index');
        }
        $owner = $this->ownership->resolve($request->request->get('owner'));
        if ($owner === null) {
            $this->addFlash('danger', 'Nieznana skrzynka - wybierz skrzynkę z listy.');
            return $this->redirectToRoute('antispam_bulk_index');
        }

        $patternType = (string)$request->request->get('pattern_type', 'exact');
        if (!in_array($patternType, self::PATTERN_TYPES, true)) {
            $patternType = 'exact';
        }
        $score = max(1, (int)$request->request->get('score', 10));
        $withScore = in_array($type, ['blacklist', 'email_blacklist'], true);

        $conf = self::TYPES[$type];
        $setter = 'set' . ucfirst($conf['field']);
        $added = 0;
        $skipped = 0;
        $seen = [];

        foreach (self::parseEntries((string)$request->request->get('entries', ''), $patternType, $score) as $entry) {
            if (\AntispamBundle\Services\PatternMatcher::validate($entry['value'], $entry['pattern_type']) !== '') {
                $skipped++;
                continue;
            }
            $key = strtolower($entry['value']);
            if (isset($seen[$key]) || $this->ownership->findDuplicate($conf['entity'], $conf['field'], $owner, $entry['value'])) {
                $skipped++;
                continue;
            }
            $seen[$key] = true;

            $cls = $conf['entity'];
            $e = new $cls();
            $e->setEmail($owner);
            $e->$setter($entry['value']);
            $e->setPatternType($entry['pattern_type']);
            if ($withScore) {
                $e->setScore($entry['score']);
            }
            $this->em->persist($e);
            $added++;
        }
        $this->em->flush();
        $this->audit('rule.import', targetType: $type, label: sprintf('%d dodanych, %d pominiętych', $added, $skipped), mailbox: $owner, details: ['added' => $added, 'skipped' => $skipped, 'pattern_type' => $patternType]);

        $this->addFlash('success', sprintf('Zaimportowano wpisy: %d (pominięte duplikaty: %d)', $added, $skipped));
        return $this->redirectToRoute('antispam_bulk_index');
    }

    /**
     * One rule per line; `#` starts a comment line. A line may also be in the
     * export format (value TAB pattern_type [TAB score] [TAB owner]) - the
     * pattern type / score columns override the form defaults, the owner
     * column is ignored (the form picks the owner). For exact and wildcard
     * rules `,` and `;` also separate entries and values are lowercased;
     * regex lines are kept verbatim (`{2,5}`, `\D` stay intact).
     *
     * @return array<int, array{value: string, pattern_type: string, score: int}>
     */
    public static function parseEntries(string $raw, string $defaultType, int $defaultScore): array
    {
        $entries = [];
        foreach (preg_split('/\r\n|\r|\n/', $raw) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $cols = array_map('trim', explode("\t", $line));
            $type = isset($cols[1]) && in_array(strtolower($cols[1]), self::PATTERN_TYPES, true) ? strtolower($cols[1]) : $defaultType;
            $score = isset($cols[2]) && ctype_digit($cols[2]) ? max(1, (int)$cols[2]) : $defaultScore;

            $values = $type === 'regex' ? [$cols[0]] : preg_split('/[,;]/', $cols[0]);
            foreach ($values as $value) {
                $value = trim($value);
                if ($value === '') {
                    continue;
                }
                $entries[] = [
                    'value' => $type === 'regex' ? $value : strtolower($value),
                    'pattern_type' => $type,
                    'score' => $score,
                ];
            }
        }
        return $entries;
    }

    #[Route('/export/{type}', name: 'antispam_bulk_export')]
    public function exportAction(Request $request, $type)
    {
        if (!isset(self::TYPES[$type])) {
            throw $this->createNotFoundException();
        }
        $conf = self::TYPES[$type];
        $owner = (string)$request->query->get('owner', '');
        $items = RuleOwnership::filterByOwner($this->em->getRepository($conf['entity'])->findBy([], ['id' => 'ASC']), $owner);

        $getter = 'get' . ucfirst($conf['field']);
        $lines = [
            '# ' . $conf['label'] . ' - eksport ' . date('c') . ($owner !== '' ? ' - skrzynka ' . $owner : ''),
            '# wartość, typ wzorca' . (method_exists($conf['entity'], 'getScore') ? ', punkty' : '') . ', skrzynka (' . RuleOwnership::ALL . ' = wszystkie) - rozdzielone tabulatorem',
        ];
        foreach ($items as $it) {
            $lines[] = $it->$getter() . "\t" . ($it->getPatternType() ?: 'exact')
                . (method_exists($it, 'getScore') ? "\t" . $it->getScore() : '')
                . "\t" . $it->getEmail();
        }

        $response = new Response(implode("\n", $lines) . "\n");
        $response->headers->set('Content-Type', 'text/plain; charset=utf-8');
        $response->headers->set('Content-Disposition', 'attachment; filename="' . $type . '.txt"');
        return $response;
    }
}
