<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\EmailWhitelist;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class EmailWhitelstController
 * @package AntispamBundle\Controller
 * @Route("/emailwhitelist")
 */
class EmailWhitelistController extends Controller
{
    /**
     *  @Route("/index", name="antispam_emailwhitelist_index")
     *  @Template()
     */
    public function indexAction(){
        $em = $this->getDoctrine()->getManager();
        $list=$em->getRepository("AntispamBundle:EmailWhitelist")->findAll();
        return array('list'=>$list);
    }

    /**
     * @Route("/add", name="antispam_emailwhitelist_add")
     *
     */
    public function addAction(Request $request){
        $em = $this->getDoctrine()->getManager();
        $email=trim($request->get('email'));
        $jest=$em->getRepository("AntispamBundle:EmailWhitelist")->findOneByWhitelistemail($email);
        if(!$jest) {
            $wpis = new EmailWhitelist();
            $wpis->setEmail($this->get('configuration')->get('email'));
            $wpis->setWhitelistemail($email);
            $em->persist($wpis);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_emailwhitelist_del")
     */
    public function delAction($id){
        $em = $this->getDoctrine()->getManager();
        $jest=$em->getRepository("AntispamBundle:EmailWhitelist")->findOneById($id);
        if($jest){
            $em->remove($jest);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_emailwhitelist_index');
    }

}
