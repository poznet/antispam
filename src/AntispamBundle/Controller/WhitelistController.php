<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Whitelist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

/**
 * @Route("/whitelist")
 */
class WhitelistController extends Controller
{
    /**
     * @Route("/index", name="antispam_whitelist_index")
     * @Template
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();
        $list = $em->getRepository('AntispamBundle:Whitelist')->findAll();
        return ['list' => $list];
    }

    /**
     * @Route("/add", name="antispam_whitelist_add")
     */
    public function addAction(Request $request)
    {
        $em = $this->getDoctrine()->getManager();
        $host = trim((string)$request->get('host'));
        $patternType = $request->get('pattern_type', Whitelist::PATTERN_EXACT);
        if (!in_array($patternType, [Whitelist::PATTERN_EXACT, Whitelist::PATTERN_WILDCARD, Whitelist::PATTERN_REGEX], true)) {
            $patternType = Whitelist::PATTERN_EXACT;
        }
        if (!$host) {
            return $this->redirectToRoute('antispam_whitelist_index');
        }
        $existing = $em->getRepository('AntispamBundle:Whitelist')->findOneBy(['host' => $host]);
        if (!$existing) {
            $entry = new Whitelist();
            $entry->setEmail($this->get('configuration')->get('email'));
            $entry->setHost($host);
            $entry->setPatternType($patternType);
            $em->persist($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_whitelist_del")
     */
    public function delAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $entry = $em->getRepository('AntispamBundle:Whitelist')->find($id);
        if ($entry) {
            $em->remove($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }
}
