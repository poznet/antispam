<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Services\SpamSignalService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Client side of the centralized spam DB: pushes this instance's locally
 * detected spam fingerprints to the configured remote hub and pulls everyone
 * else's, so each instance benefits from spam already caught elsewhere.
 *
 * Configure via the "Shared Spam Feed" settings page (feed.remote_url +
 * feed.remote_key). Run periodically (e.g. from cron):
 *
 *     php bin/console antispam:feed:sync
 */
class FeedSyncCommand extends Command
{
    protected static $defaultName = 'antispam:feed:sync';

    private $em;
    private $feed;

    public function __construct(EntityManagerInterface $em, SpamSignalService $feed)
    {
        parent::__construct();
        $this->em = $em;
        $this->feed = $feed;
    }

    protected function configure()
    {
        $this->setDescription('Push/pull spam fingerprints to/from the configured shared feed hub')
            ->addOption('push-only', null, InputOption::VALUE_NONE, 'Only push local signals')
            ->addOption('pull-only', null, InputOption::VALUE_NONE, 'Only pull remote signals')
            ->addOption('batch', null, InputOption::VALUE_REQUIRED, 'Push batch size', 1000);
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if (!$this->feed->isEnabled()) {
            $output->writeln('<comment>Shared feed is disabled (feed.enabled). Nothing to do.</comment>');
            return 0;
        }
        $url = $this->feed->getRemoteUrl();
        if ($url === '') {
            $output->writeln('<error>No remote hub configured (feed.remote_url).</error>');
            return 1;
        }
        $key = $this->feed->getRemoteKey();

        $pushOnly = (bool)$input->getOption('push-only');
        $pullOnly = (bool)$input->getOption('pull-only');

        if (!$pullOnly) {
            if (($rc = $this->push($url, $key, (int)$input->getOption('batch'), $output)) !== 0) {
                return $rc;
            }
        }
        if (!$pushOnly) {
            if (($rc = $this->pull($url, $key, $output)) !== 0) {
                return $rc;
            }
        }
        return 0;
    }

    private function push($url, $key, $batch, OutputInterface $output)
    {
        $batch = max(1, $batch);
        $repo = $this->em->getRepository(SharedSpamSignal::class);
        $lastId = $this->feed->getLastPushId();
        $sent = 0;

        while (true) {
            $rows = $repo->findLocalAfterId($lastId, $batch);
            if (!$rows) {
                break;
            }
            $signals = [];
            $maxId = $lastId;
            foreach ($rows as $row) {
                $signals[] = ['type' => $row->getType(), 'hash' => $row->getHash()];
                $maxId = max($maxId, $row->getId());
            }

            list($code, $body) = $this->http('POST', $url . '/api/feed/report', $key, ['signals' => $signals]);
            if ($code !== 200) {
                $output->writeln(sprintf('<error>Push failed (HTTP %d): %s</error>', $code, $body));
                return 1;
            }

            $sent += count($signals);
            $lastId = $maxId;
            $this->feed->setLastPushId($lastId);

            if (count($rows) < $batch) {
                break;
            }
        }

        $output->writeln(sprintf('<info>Pushed %d local signal(s).</info>', $sent));
        return 0;
    }

    private function pull($url, $key, OutputInterface $output)
    {
        $since = $this->feed->getLastPullAt();
        $query = $since ? ('?since=' . urlencode($since->format(\DateTime::ATOM))) : '';

        list($code, $body) = $this->http('GET', $url . '/api/feed/pull' . $query, $key, null);
        if ($code !== 200) {
            $output->writeln(sprintf('<error>Pull failed (HTTP %d): %s</error>', $code, $body));
            return 1;
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['signals']) || !is_array($data['signals'])) {
            $output->writeln('<error>Pull returned an unexpected payload.</error>');
            return 1;
        }

        $signals = [];
        foreach ($data['signals'] as $sig) {
            if (is_array($sig)) {
                $signals[] = ['type' => $sig['type'] ?? null, 'hash' => $sig['hash'] ?? null];
            }
        }
        $imported = $this->feed->record($signals, SharedSpamSignal::ORIGIN_REMOTE);
        $this->feed->flush();

        if (!empty($data['now'])) {
            $this->feed->setLastPullAt($data['now']);
        }

        $output->writeln(sprintf('<info>Pulled %d signal(s), imported %d.</info>', count($signals), $imported));
        return 0;
    }

    /**
     * Minimal cURL wrapper. Returns [httpCode, responseBody]; httpCode 0 on a
     * transport error (with the error text as the body).
     *
     * @return array{0:int, 1:string}
     */
    private function http($method, $url, $key, $jsonBody)
    {
        $ch = curl_init($url);
        $headers = ['X-Feed-Key: ' . $key, 'Accept: application/json'];
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        if ($jsonBody !== null) {
            $headers[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($jsonBody));
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        $body = curl_exec($ch);
        if ($body === false) {
            $err = curl_error($ch);
            curl_close($ch);
            return [0, $err];
        }
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$code, (string)$body];
    }
}
