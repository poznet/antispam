<?php

namespace AntispamBundle\Command;

use AntispamBundle\Controller\SpamFeedApiController;
use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Services\SpamSignalService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
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
#[AsCommand(name: 'antispam:feed:sync', description: 'Push/pull spam fingerprints to/from the configured shared feed hub')]
class FeedSyncCommand extends Command
{
    /** Rows asked for per pull request (the hub caps it at SpamFeedApiController::MAX_SIGNALS_PER_PULL). */
    const PULL_PAGE_SIZE = SpamFeedApiController::MAX_SIGNALS_PER_PULL;
    /** Pages per run; whatever is left is pulled on the next run. */
    const MAX_PULL_PAGES = 200;

    private $em;
    private $feed;

    public function __construct(EntityManagerInterface $em, SpamSignalService $feed)
    {
        parent::__construct();
        $this->em = $em;
        $this->feed = $feed;
    }

    protected function configure(): void
    {
        $this->addOption('push-only', null, InputOption::VALUE_NONE, 'Only push local signals')
            ->addOption('pull-only', null, InputOption::VALUE_NONE, 'Only pull remote signals')
            ->addOption('batch', null, InputOption::VALUE_REQUIRED, 'Push batch size (at most ' . SpamFeedApiController::MAX_SIGNALS_PER_REPORT . ')', SpamFeedApiController::MAX_SIGNALS_PER_REPORT);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
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
        // The hub answers 413 above its per-report limit, which would block the push forever.
        $batch = min(SpamFeedApiController::MAX_SIGNALS_PER_REPORT, max(1, $batch));
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

    /**
     * Pull everything updated since the checkpoint, page by page.
     *
     * The cursor is the hub's own (updated_at, id) of the last row received -
     * never the hub's "now", which is taken after the query and would skip
     * rows. Each run starts one second before the stored checkpoint, because
     * a row may be updated again within the second already pulled; the import
     * is idempotent (SpamSignalService::importRemote), so the overlap is safe.
     * The checkpoint only moves after a page was imported and flushed.
     */
    private function pull($url, $key, OutputInterface $output)
    {
        $checkpoint = $this->feed->getLastPullAt();
        $since = $checkpoint ? (clone $checkpoint)->modify('-1 second')->format(\DateTime::ATOM) : null;
        $afterId = 0;
        $pulled = 0;
        $imported = 0;

        for ($page = 1; $page <= self::MAX_PULL_PAGES; $page++) {
            $params = ['limit' => self::PULL_PAGE_SIZE];
            if ($since !== null) {
                $params['since'] = $since;
                if ($afterId > 0) {
                    $params['after_id'] = $afterId;
                }
            }
            list($code, $body) = $this->http('GET', $url . '/api/feed/pull?' . http_build_query($params), $key, null);
            if ($code !== 200) {
                $output->writeln(sprintf('<error>Pull failed (HTTP %d): %s</error>', $code, mb_substr((string)$body, 0, 300)));
                return 1;
            }

            $data = json_decode($body, true);
            if (!is_array($data) || !isset($data['signals']) || !is_array($data['signals'])) {
                $output->writeln('<error>Pull returned an unexpected payload.</error>');
                return 1;
            }

            $signals = [];
            $lastAt = null;
            $lastId = 0;
            foreach ($data['signals'] as $sig) {
                if (!is_array($sig)) {
                    continue;
                }
                $signals[] = ['type' => $sig['type'] ?? null, 'hash' => $sig['hash'] ?? null, 'reports' => (int)($sig['reports'] ?? 1)];
                if (!empty($sig['updated_at'])) {
                    $lastAt = (string)$sig['updated_at'];
                    $lastId = (int)($sig['id'] ?? 0);
                }
            }
            $imported += $this->feed->importRemote($signals);
            $this->feed->flush();
            $pulled += count($signals);

            if ($lastAt !== null) {
                $this->feed->setLastPullAt($lastAt);
            }

            // The hub's page size may be smaller than ours: trust its "limit".
            $limit = isset($data['limit']) ? (int)$data['limit'] : self::PULL_PAGE_SIZE;
            if (count($data['signals']) < max(1, $limit) || $lastAt === null) {
                break;
            }
            // A hub without "id" in the rows can only page by second; if a whole
            // page shares one second the cursor would not move.
            if ($lastId === 0 && $lastAt === $since) {
                $output->writeln('<comment>Hub does not support paging within one second (no row ids) - stopping; update the hub.</comment>');
                break;
            }
            $since = $lastAt;
            $afterId = $lastId;
            if ($page === self::MAX_PULL_PAGES) {
                $output->writeln(sprintf('<comment>Stopped after %d pages; the rest follows on the next run.</comment>', $page));
            }
        }

        $output->writeln(sprintf('<info>Pulled %d signal(s), imported %d.</info>', $pulled, $imported));
        return 0;
    }

    /**
     * Minimal cURL wrapper. Returns [httpCode, responseBody]; httpCode 0 on a
     * transport error (with the error text as the body). Protected so tests
     * can replace the transport.
     *
     * @return array{0:int, 1:string}
     */
    protected function http($method, $url, $key, $jsonBody)
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
