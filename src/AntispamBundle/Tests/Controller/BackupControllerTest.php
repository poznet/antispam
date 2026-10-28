<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\BackupController;
use AntispamBundle\Services\Backup\BackupExporter;
use AntispamBundle\Services\Backup\BackupFormat;
use AntispamBundle\Services\Backup\BackupImporter;
use AntispamBundle\Services\Backup\ImportReport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * "Kopia zapasowa" panel page: ROLE_ADMIN only, POST + CSRF on every action,
 * re-entering the password for an export with secrets, two-step import.
 * The exporter / importer are mocked, so no database is needed.
 */
class BackupControllerTest extends WebTestCase
{
    private const PASSWORD = 'correct-horse-battery';

    private string $hash;
    /** @var BackupExporter&MockObject */
    private $exporter;
    /** @var BackupImporter&MockObject */
    private $importer;
    private array $tmpFiles = [];

    protected function setUp(): void
    {
        $this->hash = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 4]);
        $_SERVER['ADMIN_PASSWORD_HASH'] = $_ENV['ADMIN_PASSWORD_HASH'] = $this->hash;
        $_SERVER['ADMIN_USER'] = $_ENV['ADMIN_USER'] = 'admin';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['ADMIN_PASSWORD_HASH'], $_ENV['ADMIN_PASSWORD_HASH'], $_SERVER['ADMIN_USER'], $_ENV['ADMIN_USER']);
        foreach ($this->tmpFiles as $f) {
            @unlink($f);
        }
        parent::tearDown();
    }

    private function adminClient(): KernelBrowser
    {
        $client = static::createClient();
        $client->disableReboot();
        $client->loginUser(new InMemoryUser('admin', $this->hash, ['ROLE_ADMIN']));
        $this->exporter = $this->createMock(BackupExporter::class);
        $this->importer = $this->createMock(BackupImporter::class);
        static::getContainer()->set(BackupExporter::class, $this->exporter);
        static::getContainer()->set(BackupImporter::class, $this->importer);

        return $client;
    }

    /** CSRF tokens of the index page forms, by form action. */
    private function tokens(KernelBrowser $client): array
    {
        $crawler = $client->request('GET', '/backup/');
        $this->assertResponseIsSuccessful();
        $tokens = [];
        foreach ($crawler->filterXPath('//form') as $form) {
            $tokens[$form->getAttribute('action')] = (new \Symfony\Component\DomCrawler\Crawler($form))->filterXPath('//input[@name="_token"]')->attr('value');
        }

        return $tokens;
    }

    private function flashes(KernelBrowser $client, string $type): array
    {
        return $client->getRequest()->getSession()->getFlashBag()->peek($type);
    }

    private function upload(string $content, string $name = 'backup.json'): UploadedFile
    {
        $path = tempnam(sys_get_temp_dir(), 'bkt');
        file_put_contents($path, $content);
        $this->tmpFiles[] = $path;

        return new UploadedFile($path, $name, 'application/json', null, true);
    }

    // ---- access ------------------------------------------------------------------

    public static function paths(): array
    {
        return [['/backup/'], ['/backup/export'], ['/backup/import'], ['/backup/import/apply']];
    }

    #[DataProvider('paths')]
    public function testAdminOnly(string $path)
    {
        self::bootKernel();
        [$attributes] = self::getContainer()->get('security.access_map')->getPatterns(Request::create($path));
        $this->assertSame(['ROLE_ADMIN'], $attributes, $path);
    }

    public function testControllerRequiresAdminRole()
    {
        $attributes = (new \ReflectionClass(BackupController::class))->getAttributes(IsGranted::class);
        $this->assertCount(1, $attributes);
        $this->assertSame('ROLE_ADMIN', $attributes[0]->newInstance()->attribute);
    }

    public function testAnonymousIsSentToLogin()
    {
        $client = static::createClient();
        $client->request('GET', '/backup/');
        $this->assertTrue($client->getResponse()->isRedirect(), (string)$client->getResponse()->getStatusCode());
        $this->assertStringContainsString('/login', (string)$client->getResponse()->headers->get('Location'));
    }

    public function testRoleUserIsDenied()
    {
        $client = static::createClient();
        $client->loginUser(new InMemoryUser('jan', 'x', ['ROLE_USER']));
        $client->request('GET', '/backup/');
        $this->assertNotSame(200, $client->getResponse()->getStatusCode());
    }

    #[DataProvider('paths')]
    public function testActionsArePostOnly(string $path)
    {
        if ($path === '/backup/') {
            $this->addToAssertionCount(1);
            return;
        }
        $client = $this->adminClient();
        $client->request('GET', $path);
        $this->assertSame(405, $client->getResponse()->getStatusCode());
    }

    public function testPostWithoutTokenIsRejected()
    {
        $client = $this->adminClient();
        $this->exporter->expects($this->never())->method('export');
        $this->importer->expects($this->never())->method('import');

        foreach (['/backup/export', '/backup/import', '/backup/import/apply'] as $path) {
            foreach ([[], ['_token' => 'forged']] as $body) {
                $client->request('POST', $path, $body + ['mode' => 'replace', 'sections' => ['users'], 'confirm_replace' => '1']);
                $this->assertTrue($client->getResponse()->isRedirect('/backup/'), $path);
                $this->assertStringContainsString('token', $this->flashes($client, 'danger')[0] ?? '', $path);
                $client->getRequest()->getSession()->getFlashBag()->clear();
            }
        }
    }

    // ---- export ------------------------------------------------------------------

    public function testIndexRendersTokenizedForms()
    {
        $client = $this->adminClient();
        $tokens = $this->tokens($client);
        $this->assertArrayHasKey('/backup/export', $tokens);
        $this->assertArrayHasKey('/backup/import', $tokens);
        $this->assertStringContainsString('Kopia zapasowa', $client->getResponse()->getContent());
    }

    public function testExportWithoutSecrets()
    {
        $client = $this->adminClient();
        $token = $this->tokens($client)['/backup/export'];
        $this->exporter->expects($this->once())->method('export')->with(false)->willReturn(['format' => BackupFormat::FORMAT, 'schema_version' => 1]);

        $client->request('POST', '/backup/export', ['_token' => $token, 'format' => 'json']);
        $response = $client->getResponse();
        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('attachment', $response->headers->get('Content-Disposition'));
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame(BackupFormat::FORMAT, json_decode($response->getContent(), true)['format']);
    }

    public function testExportWithSecretsNeedsConfirmAndPassword()
    {
        $client = $this->adminClient();
        $token = $this->tokens($client)['/backup/export'];
        $this->exporter->expects($this->once())->method('export')->with(true)->willReturn(['format' => BackupFormat::FORMAT, 'schema_version' => 1]);

        $client->request('POST', '/backup/export', ['_token' => $token, 'include_secrets' => '1', 'password' => self::PASSWORD]);
        $this->assertTrue($client->getResponse()->isRedirect('/backup/'), 'no confirmation');

        $client->request('POST', '/backup/export', ['_token' => $token, 'include_secrets' => '1', 'confirm_secrets' => '1', 'password' => 'wrong']);
        $this->assertTrue($client->getResponse()->isRedirect('/backup/'), 'wrong password');
        $this->assertStringContainsString('Nieprawidłowe hasło', $this->flashes($client, 'danger')[1] ?? '');

        $client->request('POST', '/backup/export', ['_token' => $token, 'include_secrets' => '1', 'confirm_secrets' => '1', 'password' => self::PASSWORD]);
        $this->assertSame(200, $client->getResponse()->getStatusCode());
        $this->assertStringContainsString('-secrets.json', $client->getResponse()->headers->get('Content-Disposition'));
    }

    // ---- import ------------------------------------------------------------------

    public function testInvalidUploadIsRejectedBeforeImport()
    {
        $client = $this->adminClient();
        $token = $this->tokens($client)['/backup/import'];
        $this->importer->expects($this->never())->method('import');

        $client->request('POST', '/backup/import', ['_token' => $token, 'mode' => 'merge', 'sections' => ['rules']], ['backup' => $this->upload('{"not":"a backup"}')]);
        $this->assertTrue($client->getResponse()->isRedirect('/backup/'));
        $this->assertStringContainsString('Nieprawidłowy plik', $this->flashes($client, 'danger')[0] ?? '');

        $client->request('POST', '/backup/import', ['_token' => $token, 'mode' => 'merge', 'sections' => ['rules']]);
        $this->assertStringContainsString('Wybierz plik', $this->flashes($client, 'danger')[1] ?? '');

        $client->request('POST', '/backup/import', ['_token' => $token, 'mode' => 'merge', 'sections' => ['phishing']], ['backup' => $this->upload('{}')]);
        $this->assertStringContainsString('sekcję', $this->flashes($client, 'danger')[2] ?? '');
    }

    public function testPreviewThenApply()
    {
        $client = $this->adminClient();
        $token = $this->tokens($client)['/backup/import'];
        $json = BackupFormat::encode(['format' => BackupFormat::FORMAT, 'schema_version' => 1, 'rules' => ['blacklist' => [['owner' => '*', 'value' => 'x.pl']]]]);

        $calls = [];
        $this->importer->method('import')->willReturnCallback(function ($data, $sections, $mode, $dryRun, $protect) use (&$calls) {
            $calls[] = [$sections, $mode, $dryRun, $protect];
            $report = new ImportReport($mode, $dryRun, $sections);
            $report->count('rules', 'created');
            return $report;
        });

        $crawler = $client->request('POST', '/backup/import', ['_token' => $token, 'mode' => 'replace', 'sections' => ['rules', 'dnsbl']], ['backup' => $this->upload($json)]);
        $this->assertResponseIsSuccessful();
        $this->assertStringContainsString('podgląd', $client->getResponse()->getContent());
        $this->assertSame([[['rules', 'dnsbl'], 'replace', true, 'admin']], $calls);

        $form = $crawler->filterXPath('//form[@action="/backup/import/apply"]');
        $applyToken = $form->filterXPath('//input[@name="_token"]')->attr('value');
        $pendingId = $form->filterXPath('//input[@name="pending_id"]')->attr('value');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $pendingId);
        $pendingFile = static::getContainer()->getParameter('kernel.project_dir') . '/var/backup-import/' . $pendingId . '.json';
        $this->tmpFiles[] = $pendingFile;
        $this->assertFileExists($pendingFile);

        // replace mode needs the explicit confirmation
        $client->request('POST', '/backup/import/apply', ['_token' => $applyToken, 'pending_id' => $pendingId, 'mode' => 'replace', 'sections' => ['rules', 'dnsbl']]);
        $this->assertStringContainsString('potwierdzenie', $this->flashes($client, 'danger')[0] ?? '');
        $this->assertCount(1, $calls);

        // a pending id that is not this session's
        $client->request('POST', '/backup/import/apply', ['_token' => $applyToken, 'pending_id' => str_repeat('a', 32), 'mode' => 'merge', 'sections' => ['rules']]);
        $this->assertStringContainsString('wygasł', $this->flashes($client, 'danger')[1] ?? '');
        $this->assertCount(1, $calls);

        $client->request('POST', '/backup/import/apply', ['_token' => $applyToken, 'pending_id' => $pendingId, 'mode' => 'replace', 'sections' => ['rules', 'dnsbl'], 'confirm_replace' => '1']);
        $this->assertTrue($client->getResponse()->isRedirect('/backup/'));
        $this->assertSame([['rules', 'dnsbl'], 'replace', false, 'admin'], $calls[1]);
        $this->assertStringContainsString('Import zakończony', $this->flashes($client, 'success')[0] ?? '');
        $this->assertFileDoesNotExist($pendingFile, 'the pending upload is removed after use');

        // and cannot be applied twice
        $client->request('POST', '/backup/import/apply', ['_token' => $applyToken, 'pending_id' => $pendingId, 'mode' => 'merge', 'sections' => ['rules']]);
        $this->assertCount(2, $calls);
    }
}
