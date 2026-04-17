<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailBlacklist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

/**
 * @Route("/emailblacklst")
 */
class EmailBlacklistController extends Controller
{
    /**
     * @Route("/index", name="antispam_emailblacklist_index")
     * @Template
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();
        $list = $em->getRepository('AntispamBundle:EmailBlacklist')->findAll();
        return ['list' => $list];
    }

    /**
     * @Route("/add", name="antispam_emailblacklist_add")
     */
    public function addAction(Request $request)
    {
        $em = $this->getDoctrine()->getManager();
        $email = trim((string)$request->get('email'));
        $patternType = $request->get('pattern_type', EmailBlacklist::PATTERN_EXACT);
        $score = (int)$request->get('score', 10);
        if (!in_array($patternType, [EmailBlacklist::PATTERN_EXACT, EmailBlacklist::PATTERN_WILDCARD, EmailBlacklist::PATTERN_REGEX], true)) {
            $patternType = EmailBlacklist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailblacklist_index');
        }
        $existing = $em->getRepository('AntispamBundle:EmailBlacklist')->findOneBy(['blacklistemail' => $email]);
        if (!$existing) {
            $entry = new EmailBlacklist();
            $entry->setEmail($this->get('configuration')->get('email'));
            $entry->setBlacklistemail($email);
            $entry->setPatternType($patternType);
            $entry->setScore(max(1, $score));
            $em->persist($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_emailblacklist_del")
     */
    public function delAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $entry = $em->getRepository('AntispamBundle:EmailBlacklist')->find($id);
        if ($entry) {
            $em->remove($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }
}
