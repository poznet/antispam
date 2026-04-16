<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Bulk import/export for all four rule lists.
 *
 * @Route("/bulk")
 */
class BulkImportController extends Controller
{
    const TYPES = [
        'blacklist'       => ['entity' => Blacklist::class,      'field' => 'host',           'label' => 'Domain blacklist'],
        'whitelist'       => ['entity' => Whitelist::class,      'field' => 'host',           'label' => 'Domain whitelist'],
        'email_blacklist' => ['entity' => EmailBlacklist::class, 'field' => 'blacklistemail', 'label' => 'Email blacklist'],
        'email_whitelist' => ['entity' => EmailWhitelist::class, 'field' => 'whitelistemail', 'label' => 'Email whitelist'],
    ];

    /**
     * @Template()
     * @Route("/", name="antispam_bulk_index")
     */
    public function indexAction()
    {
        return ['types' => self::TYPES];
    }

    /**
     * @Route("/import/{type}", name="antispam_bulk_import", methods={"POST"})
     */
    public function importAction(Request $request, $type)
    {
        if (!isset(self::TYPES[$type])) {
            $this->addFlash('danger', 'Unknown list type');
            return $this->redirectToRoute('antispam_bulk_index');
        }

        $raw = (string)$request->get('entries', '');
        $patternType = $request->get('pattern_type', 'exact');
        $score = (int)$request->get('score', 10);
        $email = $this->get('configuration')->get('email');

        $entries = array_values(array_filter(array_map(function ($line) {
            $line = trim(preg_replace('/[,;]/', "\n", $line));
            return strtolower(preg_replace('/^#.*/', '', $line));
        }, preg_split('/\r?\n/', $raw))));

        $conf = self::TYPES[$type];
        $em = $this->getDoctrine()->getManager();
        $added = 0;
        $skipped = 0;

        foreach ($entries as $value) {
            if (!$value) { continue; }
            $setter = 'set' . ucfirst($conf['field']);
            $existing = $em->getRepository($conf['entity'])->findOneBy([
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
            $em->persist($e);
            $added++;
        }
        $em->flush();

        $this->addFlash('success', sprintf('Imported %d entries (skipped %d duplicates)', $added, $skipped));
        return $this->redirectToRoute('antispam_bulk_index');
    }

    /**
     * @Route("/export/{type}", name="antispam_bulk_export")
     */
    public function exportAction($type)
    {
        if (!isset(self::TYPES[$type])) {
            throw $this->createNotFoundException();
        }
        $conf = self::TYPES[$type];
        $em = $this->getDoctrine()->getManager();
        $items = $em->getRepository($conf['entity'])->findAll();

        $getter = 'get' . ucfirst($conf['field']);
        $lines = ['# ' . $conf['label'] . ' - exported ' . date('c')];
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
