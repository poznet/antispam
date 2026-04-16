<?php

namespace AntispamBundle\Controller;

use Ddeboer\Imap\Exception\MessageUnsupportedEncodeException;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;

/**
 * @Route("/spambox")
 */
class SpamboxController extends Controller
{
    /**
     * @Template()
     * @Route("/index", name="antispam_spambox_index")
     */
    public function indexAction()
    {
        return ['messages' => $this->loadFolder($this->get('antispam.inbox')->getSpamFolderName())];
    }

    /**
     * @Template()
     * @Route("/quarantine", name="antispam_spambox_quarantine")
     */
    public function quarantineAction()
    {
        return ['messages' => $this->loadFolder($this->get('antispam.inbox')->getQuarantineFolderName())];
    }

    /**
     * Move a message from SPAM or QUARANTINE back to INBOX.
     *
     * @Route("/restore/{folder}/{id}", name="antispam_spambox_restore")
     */
    public function restoreAction($folder, $id)
    {
        $allowed = [
            $this->get('antispam.inbox')->getSpamFolderName(),
            $this->get('antispam.inbox')->getQuarantineFolderName(),
        ];
        if (!in_array($folder, $allowed, true)) {
            $this->addFlash('danger', 'Invalid folder');
            return $this->redirectToRoute('antispam_spambox_index');
        }

        try {
            $messages = $this->get('antispam.inbox')->getInbox($folder);
            $msg = $this->get('antispam.inbox')->getMessage((int)$id);
            $inboxMailbox = $this->get('antispam.connection')->getConnection()->getMailbox('INBOX');
            $msg->move($inboxMailbox);
            $this->addFlash('success', 'Message restored to INBOX');
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Restore failed: ' . $e->getMessage());
        }

        return $this->redirectToRoute($folder === 'QUARANTINE'
            ? 'antispam_spambox_quarantine'
            : 'antispam_spambox_index');
    }

    /**
     * Recent score log with reasons - "why did X get flagged".
     *
     * @Template()
     * @Route("/scorelog", name="antispam_spambox_scorelog")
     */
    public function scorelogAction()
    {
        $em = $this->getDoctrine()->getManager();
        $logs = $em->getRepository('AntispamBundle:SpamScoreLog')->findRecent(100);
        $stats = $em->getRepository('AntispamBundle:SpamScoreLog')->statsByDecision(new \DateTime('-30 days'));
        return ['logs' => $logs, 'stats' => $stats];
    }

    private function loadFolder($folderName)
    {
        $messages = [];
        try {
            $list = $this->get('antispam.inbox')->getInbox($folderName);
        } catch (\Throwable $e) {
            return $messages;
        }

        $count = 0;
        foreach ($list as $m) {
            if ($count++ >= 20) break;
            try {
                $msg = $this->get('antispam.inbox')->getMessage($m->getNumber());
                $messages[] = [
                    'subject' => (string)$msg->getSubject(),
                    'from' => $msg->getFrom(),
                    'content' => $msg->getBodyHtml(),
                    'date' => $msg->getDate(),
                    'id' => $msg->getNumber(),
                ];
            } catch (MessageUnsupportedEncodeException $e) {
                continue;
            } catch (\Throwable $e) {
                continue;
            }
        }
        return $messages;
    }
}
