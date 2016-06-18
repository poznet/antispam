<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\Whitelist;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\Request;

/**
 *
 * Class WhitelistController
 * @package AntispamBundle\Controller
 * @Route("/whitelist")
 */
class WhitelistController extends Controller
{

    /**
     * @Route("/index", name="antispam_whitelist_index")
     * @Template
     */
    public function indexAction(){
        $em = $this->getDoctrine()->getManager();
        $list=$em->getRepository("AntispamBundle:Whitelist")->findAll();
        return array('list'=>$list);
    }

    /**
     * @Route("/add", name="antispam_whitelist_add")
     *
     */
    public function addAction(Request $request){
        $em = $this->getDoctrine()->getManager();
        $host=trim($request->get('host'));
        $jest=$em->getRepository("AntispamBundle:Whitelist")->findOneByHost($host);
        if(!$jest) {
            $wpis = new Whitelist();
            $wpis->setEmail($this->get('configuration')->get('email'));
            $wpis->setHost($host);
            $em->persist($wpis);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

    /**
     * @Route("/del/{id}", name="antispam_whitelist_del")
     */
    public function delAction($id){
        $em = $this->getDoctrine()->getManager();
        $jest=$em->getRepository("AntispamBundle:Whitelist")->findOneById($id);
        if($jest){
            $em->remove($jest);
            $em->flush();
        }
        return $this->redirectToRoute('antispam_whitelist_index');
    }

}
