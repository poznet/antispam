<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailBlacklist;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class EmailBlacklistController
 * @package AntispamBundle\Controller
 * @Route("/emailblacklst")
 */
class EmailBlacklistController extends Controller
{
    /**
     * @Route("/index", name="antispam_emailblacklist_index")
     * @Template
     */
    public function indexAction(){
        $em = $this->getDoctrine()->getManager();
        $list=$em->getRepository("AntispamBundle:EmailBlacklist")->findAll();
        return array('list'=>$list);
    }

    /**
     * @Route("/add", name="antispam_emailblacklist_add")
     *
     */
    public function addAction(Request $request){
        $em = $this->getDoctrine()->getManager();
        $email=trim($request->get('email'));
        $jest=$em->getRepository("AntispamBundle:EmailBlacklist")->findOneByBlacklistemail($email);
        if(!$jest) {
            $wpis = new EmailBlacklist();
            $wpis->setEmail($this->get('configuration')->get('email'));
            $wpis->setBlacklistemail($email);
            $em->persist($wpis);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_emailblacklist_del")
     */
    public function delAction($id){
        $em = $this->getDoctrine()->getManager();
        $jest=$em->getRepository("AntispamBundle:EmailBlacklist")->findOneById($id);
        if($jest){
            $em->remove($jest);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailblacklist_index');
    }

}
