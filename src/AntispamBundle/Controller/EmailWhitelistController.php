<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailWhitelist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;

/**
 * @Route("/emailwhitelist")
 */
class EmailWhitelistController extends Controller
{
    /**
     * @Route("/index", name="antispam_emailwhitelist_index")
     * @Template()
     */
    public function indexAction()
    {
        $em = $this->getDoctrine()->getManager();
        $list = $em->getRepository('AntispamBundle:EmailWhitelist')->findAll();
        return ['list' => $list];
    }

    /**
     * @Route("/add", name="antispam_emailwhitelist_add")
     */
    public function addAction(Request $request)
    {
        $em = $this->getDoctrine()->getManager();
        $email = trim((string)$request->get('email'));
        $patternType = $request->get('pattern_type', EmailWhitelist::PATTERN_EXACT);
        if (!in_array($patternType, [EmailWhitelist::PATTERN_EXACT, EmailWhitelist::PATTERN_WILDCARD, EmailWhitelist::PATTERN_REGEX], true)) {
            $patternType = EmailWhitelist::PATTERN_EXACT;
        }
        if (!$email) {
            return $this->redirectToRoute('antispam_emailwhitelist_index');
        }
        $existing = $em->getRepository('AntispamBundle:EmailWhitelist')->findOneBy(['whitelistemail' => $email]);
        if (!$existing) {
            $entry = new EmailWhitelist();
            $entry->setEmail($this->get('configuration')->get('email'));
            $entry->setWhitelistemail($email);
            $entry->setPatternType($patternType);
            $em->persist($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_emailwhitelist_del")
     */
    public function delAction($id)
    {
        $em = $this->getDoctrine()->getManager();
        $entry = $em->getRepository('AntispamBundle:EmailWhitelist')->find($id);
        if ($entry) {
            $em->remove($entry);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }
}
