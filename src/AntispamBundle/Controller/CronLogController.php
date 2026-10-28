<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Entity\CronRun;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Attribute\Template;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

/** Runs of the periodic commands recorded by `antispam:cron:run`. */
#[Route('/cron')]
class CronLogController extends AbstractController
{
    public function __construct(private EntityManagerInterface $em)
    {
    }

    #[Route('/logs', name: 'antispam_cron_logs', methods: ['GET'])]
    #[Template('@Antispam/CronLog/index.html.twig')]
    public function indexAction(Request $request)
    {
        $repo = $this->em->getRepository(CronRun::class);
        $commands = $repo->distinctCommands();
        $command = in_array($request->query->get('command'), $commands, true) ? $request->query->get('command') : null;
        $failed = $request->query->getBoolean('failed');

        return [
            'runs' => $repo->findRecent(200, $command, $failed),
            'commands' => $commands,
            'command' => $command,
            'failed' => $failed,
            'retention' => CronRun::RETENTION_DAYS,
            // A run with no end after this long was killed (container restart, OOM...).
            'stale_before' => new \DateTime('-2 hours'),
        ];
    }
}
