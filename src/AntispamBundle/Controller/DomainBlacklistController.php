<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Blacklist;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 *
 * Class DomainBlacklistController
 * @package AntispamBundle\Controller
 * @Route("/domainblacklst")
 */
class DomainBlacklistController extends Controller
{

    /**
     * @Route("/index", name="antispam_blacklist_index")
     * @Template
     */
    public function indexAction(){
        $em = $this->getDoctrine()->getManager();
        $list=$em->getRepository("AntispamBundle:Blacklist")->findAll();
        return array('list'=>$list);
    }

    /**
     * @Route("/add", name="antispam_blacklist_add")
     *
     */
    public function addAction(Request $request){
        $em = $this->getDoctrine()->getManager();
        $host=trim($request->get('host'));
        $jest=$em->getRepository("AntispamBundle:Blacklist")->findOneByHost($host);
        if(!$jest) {
            $wpis = new Blacklist();
            $wpis->setEmail($this->get('configuration')->get('email'));
            $wpis->setHost($host);
            $em->persist($wpis);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_blacklist_del")
     */
    public function delAction($id){
        $em = $this->getDoctrine()->getManager();
        $jest=$em->getRepository("AntispamBundle:Blacklist")->findOneById($id);
        if($jest){
            $em->remove($jest);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_blacklist_index');
    }

}
