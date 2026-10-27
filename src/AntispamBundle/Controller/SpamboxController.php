<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\SpamScoreLog;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\InboxService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/spambox')]
class SpamboxController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $em,
        private InboxService $inbox,
        private ConnectionService $connection,
    ) {
    }

    #[Route('/index', name: 'antispam_spambox_index')]
    #[Template('@Antispam/Spambox/index.html.twig')]
    public function indexAction()
    {
        return ['messages' => $this->loadFolder($this->inbox->getSpamFolderName())];
    }

    #[Route('/quarantine', name: 'antispam_spambox_quarantine')]
    #[Template('@Antispam/Spambox/quarantine.html.twig')]
    public function quarantineAction()
    {
        return ['messages' => $this->loadFolder($this->inbox->getQuarantineFolderName())];
    }

    /** Move a message from SPAM or QUARANTINE back to INBOX. */
    #[Route('/restore/{folder}/{id}', name: 'antispam_spambox_restore')]
    public function restoreAction($folder, $id)
    {
        $allowed = [
            $this->inbox->getSpamFolderName(),
            $this->inbox->getQuarantineFolderName(),
        ];
        if (!in_array($folder, $allowed, true)) {
            $this->addFlash('danger', 'Nieprawidłowy folder');
            return $this->redirectToRoute('antispam_spambox_index');
        }

        try {
            $messages = $this->inbox->getInbox($folder);
            $msg = $this->inbox->getMessage((int)$id);
            $inboxMailbox = $this->connection->getConnection()->getMailbox('INBOX');
            $msg->move($inboxMailbox);
            $this->inbox->expunge();
            $this->addFlash('success', 'Wiadomość przywrócona do INBOX');
        } catch (\Throwable $e) {
            $this->addFlash('danger', 'Przywracanie nie powiodło się: ' . $e->getMessage());
        }

        return $this->redirectToRoute($folder === 'QUARANTINE'
            ? 'antispam_spambox_quarantine'
            : 'antispam_spambox_index');
    }

    /** Recent score log with reasons - "why did X get flagged". */
    #[Route('/scorelog', name: 'antispam_spambox_scorelog')]
    #[Template('@Antispam/Spambox/scorelog.html.twig')]
    public function scorelogAction()
    {
        $logs = $this->em->getRepository(SpamScoreLog::class)->findRecent(100);
        $stats = $this->em->getRepository(SpamScoreLog::class)->statsByDecision(new \DateTime('-30 days'));
        return ['logs' => $logs, 'stats' => $stats];
    }

    private function loadFolder($folderName)
    {
        $messages = [];
        try {
            $list = $this->inbox->getInbox($folderName);
        } catch (\Throwable $e) {
            return $messages;
        }

        $count = 0;
        foreach ($list as $m) {
            if ($count++ >= 20) break;
            try {
                $msg = $this->inbox->getMessage($m->getNumber());
                $from = $msg->getFrom();
                $messages[] = [
                    'subject' => (string)$msg->getSubject(),
                    'from' => $from ? $from->getFullAddress() : '',
                    'content' => $msg->getBodyHtml(),
                    'date' => $msg->getDate(),
                    'id' => $msg->getNumber(),
                ];
            } catch (\Throwable $e) {
                continue;
            }
        }
        return $messages;
    }
}
