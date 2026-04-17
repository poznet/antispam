<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

/**
 * @Route("/domainblacklst")
 */
class DomainBlacklistController extends Controller
{
    /**
     * @Route("/index", name="antispam_blacklist_index")
     * @Template
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();
        $list = $em->getRepository('AntispamBundle:Blacklist')->findAll();
        return ['list' => $list];
    }

    /**
     * @Route("/add", name="antispam_blacklist_add")
     */
    public function addAction(Request $request)
    {
        $em = $this->getDoctrine()->getManager();
        $host = trim((string)$request->get('host'));
        $patternType = $request->get('pattern_type', Blacklist::PATTERN_EXACT);
        $score = (int)$request->get('score', 10);
        if (!in_array($patternType, [Blacklist::PATTERN_EXACT, Blacklist::PATTERN_WILDCARD, Blacklist::PATTERN_REGEX], true)) {
            $patternType = Blacklist::PATTERN_EXACT;
        }

        if (!$host) {
            return $this->redirectToRoute('antispam_blacklist_index');
        }

        $existing = $em->getRepository('AntispamBundle:Blacklist')->findOneBy(['host' => $host]);
        if (!$existing) {
            $entry = new Blacklist();
            $entry->setEmail($this->get('configuration')->get('email'));
            $entry->setHost($host);
            $entry->setPatternType($patternType);
            $entry->setScore(max(1, $score));
            $em->persist($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_blacklist_del")
     */
    public function delAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $entry = $em->getRepository('AntispamBundle:Blacklist')->find($id);
        if ($entry) {
            $em->remove($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }
}
