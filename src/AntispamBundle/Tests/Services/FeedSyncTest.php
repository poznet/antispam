<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Command\FeedSyncCommand;
use AntispamBundle\Controller\SpamFeedApiController;
use AntispamBundle\Entity\SharedSpamSignal;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\SpamSignalService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\HttpFoundation\Request;

/**
 * Client <-> hub sync, end to end over two in-memory databases: the client's
 * FeedSyncCommand talks to the real SpamFeedApiController of the hub through
 * a fake transport. Covers pull pagination (rows sharing one second), the
 * checkpoint, echo of our own pushes (no self-corroboration) and the push
 * batch cap.
 */
class FeedSyncTest extends TestCase
{
    const KEY = 'hub-key-0123456789';

    private EntityManager $hubEm;
    private EntityManager $clientEm;
    private SpamSignalService $hubFeed;
    private SpamSignalService $clientFeed;
    private ConfigService $clientConfig;
    /** @var array<int, array{method:string, url:string, body:mixed}> */
    public array $requests = [];
    /** Page size the fake hub enforces (a hub may cap below the client's request). */
    public int $hubPageSize = 5;

    private static function em(): EntityManager
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($em))->createSchema($em->getMetadataFactory()->getAllMetadata());
        return $em;
    }

    protected function setUp(): void
    {
        $this->hubEm = self::em();
        $hubConfig = new ConfigService($this->hubEm);
        $hubConfig->set('feed.server_key', self::KEY);
        $this->hubFeed = new SpamSignalService($this->hubEm, $hubConfig);

        $this->clientEm = self::em();
        $this->clientConfig = new ConfigService($this->clientEm);
        $this->clientConfig->set('feed.enabled', '1');
        $this->clientConfig->set('feed.remote_url', 'https://hub.example');
        $this->clientConfig->set('feed.remote_key', self::KEY);
        $this->clientFeed = new SpamSignalService($this->clientEm, $this->clientConfig);
    }

    private function command(): CommandTester
    {
        $test = $this;
        $hub = new SpamFeedApiController($this->hubEm, $this->hubFeed);
        $command = new class($this->clientEm, $this->clientFeed, $hub, $test) extends FeedSyncCommand {
            public function __construct($em, $feed, private SpamFeedApiController $hub, private FeedSyncTest $test)
            {
                parent::__construct($em, $feed);
            }

            protected function http($method, $url, $key, $jsonBody)
            {
                $this->test->requests[] = ['method' => $method, 'url' => $url, 'body' => $jsonBody];
                $path = (string)parse_url($url, PHP_URL_PATH);
                parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
                if ($path === '/api/feed/pull') {
                    $query['limit'] = min((int)($query['limit'] ?? 5000), $this->test->hubPageSize);
                }
                $request = Request::create($path, $method, $query, [], [], [], $jsonBody !== null ? json_encode($jsonBody) : null);
                $request->headers->set('X-Feed-Key', $key);
                $response = $path === '/api/feed/pull' ? $this->hub->pullAction($request) : $this->hub->reportAction($request);
                return [$response->getStatusCode(), (string)$response->getContent()];
            }
        };
        return new CommandTester($command);
    }

    private function hubSignal(string $seed, int $reports, string $updatedAt, string $origin = SharedSpamSignal::ORIGIN_REMOTE): SharedSpamSignal
    {
        $s = (new SharedSpamSignal())->setType(SharedSpamSignal::TYPE_BODY)->setHash(hash('sha256', $seed))
            ->setOrigin($origin)->setReports($reports)->setUpdatedAt(new \DateTime($updatedAt));
        $this->hubEm->persist($s);
        return $s;
    }

    private function clientSignal(string $seed): ?SharedSpamSignal
    {
        return $this->clientEm->getRepository(SharedSpamSignal::class)->findOneBy(['type' => SharedSpamSignal::TYPE_BODY, 'hash' => hash('sha256', $seed)]);
    }

    private function pullRequests(): array
    {
        return array_values(array_filter($this->requests, fn($r) => str_contains($r['url'], '/api/feed/pull')));
    }

    public function testPullPaginatesThroughRowsSharingOneSecond()
    {
        // 12 rows, 8 of them in the same second - more than one 5-row page.
        for ($i = 0; $i < 8; $i++) {
            $this->hubSignal('same-second-' . $i, 2, '2026-10-01 10:00:00');
        }
        for ($i = 0; $i < 4; $i++) {
            $this->hubSignal('later-' . $i, 1, '2026-10-01 10:00:0' . ($i + 1));
        }
        $this->hubEm->flush();

        $tester = $this->command();
        $this->assertSame(0, $tester->execute(['--pull-only' => true]));

        $this->assertSame(12, $this->clientEm->getRepository(SharedSpamSignal::class)->count([]));
        $this->assertCount(3, $this->pullRequests(), '5 + 5 + 2 rows');
        $this->assertStringContainsString('after_id=', $this->pullRequests()[1]['url']);
        $this->assertSame(2, $this->clientSignal('same-second-7')->getReports());
        $this->assertSame(SharedSpamSignal::ORIGIN_REMOTE, $this->clientSignal('later-3')->getOrigin());

        // Checkpoint = hub time of the last row received, not the hub's "now".
        $this->assertEquals(new \DateTime('2026-10-01 10:00:04'), $this->clientFeed->getLastPullAt());
    }

    public function testNextRunOverlapsOneSecondAndIsIdempotent()
    {
        $this->hubSignal('a', 3, '2026-10-01 10:00:00');
        $this->hubSignal('b', 1, '2026-10-01 10:00:05');
        $this->hubEm->flush();
        $this->command()->execute(['--pull-only' => true]);

        // Updated on the hub within the already-pulled second.
        $late = $this->hubSignal('c', 1, '2026-10-01 10:00:05');
        $this->hubEm->flush();
        $this->requests = [];
        $this->command()->execute(['--pull-only' => true]);

        $this->assertStringContainsString('since=' . urlencode((new \DateTime('2026-10-01 10:00:04'))->format(\DateTime::ATOM)), $this->pullRequests()[0]['url']);
        $this->assertNotNull($this->clientSignal('c'), 'row written in the checkpoint second is not lost');
        $this->assertSame(1, $this->clientSignal('b')->getReports(), 're-pulled row is not counted twice');
        $this->assertSame(3, $this->clientSignal('a')->getReports());
        $this->assertNotNull($late->getId());
    }

    /** Our own pushed signal comes back from the hub: it must not count as a second report. */
    public function testEchoOfOwnPushDoesNotCorroborate()
    {
        $this->clientFeed->record([['type' => SharedSpamSignal::TYPE_BODY, 'hash' => hash('sha256', 'mine')]], SharedSpamSignal::ORIGIN_LOCAL);
        $this->clientFeed->flush();

        $this->assertSame(0, $this->command()->execute([]));

        $mine = $this->clientSignal('mine');
        $this->clientEm->refresh($mine);
        $this->assertSame(1, $mine->getReports());
        $this->assertSame(SharedSpamSignal::ORIGIN_LOCAL, $mine->getOrigin());
        $this->clientConfig->set('feed.min_reports', '2');
        $this->assertSame([], $this->clientFeed->matchSignals([['type' => SharedSpamSignal::TYPE_BODY, 'hash' => hash('sha256', 'mine')]]));

        // A second instance reports it too: now it is corroborated.
        $hubRow = $this->hubEm->getRepository(SharedSpamSignal::class)->findOneBy(['hash' => hash('sha256', 'mine')]);
        $hubRow->addReport()->setUpdatedAt(new \DateTime('+1 minute'));
        $this->hubEm->flush();
        $this->command()->execute(['--pull-only' => true]);
        $this->clientEm->refresh($mine);
        $this->assertSame(2, $mine->getReports());
    }

    public function testPushBatchIsCappedAtTheHubLimit()
    {
        $signals = [];
        for ($i = 0; $i < SpamFeedApiController::MAX_SIGNALS_PER_REPORT + 5; $i++) {
            $signals[] = ['type' => SharedSpamSignal::TYPE_SENDER, 'hash' => hash('sha256', 'push-' . $i)];
        }
        $this->clientFeed->record($signals, SharedSpamSignal::ORIGIN_LOCAL);
        $this->clientFeed->flush();

        $this->assertSame(0, $this->command()->execute(['--push-only' => true, '--batch' => 2000]));

        $pushes = array_values(array_filter($this->requests, fn($r) => $r['method'] === 'POST'));
        $this->assertCount(2, $pushes);
        $this->assertCount(SpamFeedApiController::MAX_SIGNALS_PER_REPORT, $pushes[0]['body']['signals']);
        $this->assertSame(SpamFeedApiController::MAX_SIGNALS_PER_REPORT + 5, $this->hubEm->getRepository(SharedSpamSignal::class)->count([]));
    }
}
