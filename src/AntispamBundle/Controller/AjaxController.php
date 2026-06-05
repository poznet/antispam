<?php

namespace AntispamBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;

/**
 * @Route("/ajax")
 */
class AjaxController extends Controller
{
    /**
     * @Route("/getmsg/{id}", requirements={"id"="\d+"})
     */
    public function getMsgAction($id)
    {
        $id = (int)$id;
        $this->get('antispam.message')->getId($id);
        $this->get('antispam.inbox')->getInbox($this->get('antispam.inbox')->getSpamFolderName());
        $msg = $this->get('antispam.inbox')->getMessage($id);

        return new JsonResponse([
            'id' => $msg ? $msg->getNumber() : null,
            'subject' => $msg ? (string)$msg->getSubject() : null,
        ]);
    }
}
