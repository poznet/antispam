<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\ConfigService;
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
    public function __construct(
        private EntityManagerInterface $em,
        private ConfigService $config,
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
        return ['types' => self::TYPES];
    }

    #[Route('/import/{type}', name: 'antispam_bulk_import', methods: ['POST'])]
    public function importAction(Request $request, $type)
    {
        if (!isset(self::TYPES[$type])) {
            $this->addFlash('danger', 'Nieznany typ listy');
            return $this->redirectToRoute('antispam_bulk_index');
        }

        $raw = (string)$request->request->get('entries', '');
        $patternType = $request->request->get('pattern_type', 'exact');
        $score = (int)$request->request->get('score', 10);
        $email = $this->config->get('email');

        $entries = array_values(array_filter(array_map(function ($line) {
            $line = trim(preg_replace('/[,;]/', "\n", $line));
            return strtolower(preg_replace('/^#.*/', '', $line));
        }, preg_split('/\r?\n/', $raw))));

        $conf = self::TYPES[$type];
        $added = 0;
        $skipped = 0;

        foreach ($entries as $value) {
            if (!$value) { continue; }
            $setter = 'set' . ucfirst($conf['field']);
            $existing = $this->em->getRepository($conf['entity'])->findOneBy([
                $conf['field'] => $value,
                'email' => $email,
            ]);
            if ($existing) { $skipped++; continue; }

            $cls = $conf['entity'];
            $e = new $cls();
            $e->setEmail($email);
            $e->$setter($value);
            if (method_exists($e, 'setPatternType')) {
                $e->setPatternType(in_array($patternType, ['exact', 'wildcard', 'regex'], true) ? $patternType : 'exact');
            }
            if (method_exists($e, 'setScore') && in_array($type, ['blacklist', 'email_blacklist'], true)) {
                $e->setScore(max(1, $score));
            }
            $this->em->persist($e);
            $added++;
        }
        $this->em->flush();

        $this->addFlash('success', sprintf('Zaimportowano wpisy: %d (pominięte duplikaty: %d)', $added, $skipped));
        return $this->redirectToRoute('antispam_bulk_index');
    }

    #[Route('/export/{type}', name: 'antispam_bulk_export')]
    public function exportAction($type)
    {
        if (!isset(self::TYPES[$type])) {
            throw $this->createNotFoundException();
        }
        $conf = self::TYPES[$type];
        $items = $this->em->getRepository($conf['entity'])->findAll();

        $getter = 'get' . ucfirst($conf['field']);
        $lines = ['# ' . $conf['label'] . ' - eksport ' . date('c')];
        foreach ($items as $it) {
            $patternType = method_exists($it, 'getPatternType') ? $it->getPatternType() : 'exact';
            $lines[] = $it->$getter() . "\t" . $patternType
                . (method_exists($it, 'getScore') ? "\t" . $it->getScore() : '');
        }

        $response = new Response(implode("\n", $lines) . "\n");
        $response->headers->set('Content-Type', 'text/plain; charset=utf-8');
        $response->headers->set('Content-Disposition', 'attachment; filename="' . $type . '.txt"');
        return $response;
    }
}
