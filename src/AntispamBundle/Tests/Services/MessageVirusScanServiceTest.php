<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Whitelist;
use AntispamBundle\Services\AttachmentPolicyAnalyzer;
use AntispamBundle\Services\CertHoleService;
use AntispamBundle\Services\ClamavService;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\DnsblService;
use AntispamBundle\Services\HeaderAnalyzer;
use AntispamBundle\Services\ImpersonationAnalyzer;
use AntispamBundle\Services\MessageVirusScanService;
use AntispamBundle\Services\RawMessageScanner;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SpamSignalService;
use AntispamBundle\Services\UrlAnalyzer;
use AntispamBundle\Services\VirusTotalService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/** "Sprawdź tę wiadomość": ClamAV + VirusTotal first, then the rules (a virus beats a whitelist). */
class MessageVirusScanServiceTest extends TestCase
{
    private const EICAR = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    private EntityManager $em;
    private ConfigService $config;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 2) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
        foreach (['scoring.header_check_enabled', 'scoring.dnsbl_enabled', 'impersonation.enabled', 'url.enabled', 'attachment.policy_enabled'] as $k) {
            $this->config->set($k, false);
        }
    }

    private static function raw(): string
    {
        return "From: Kurier <info@paczki.example>\r\nTo: jan@firma.pl\r\nSubject: Paczka\r\nMIME-Version: 1.0\r\n"
            . "Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nW załączniku.\r\n"
            . "--b\r\nContent-Type: application/octet-stream; name=\"faktura.exe\"\r\nContent-Disposition: attachment; filename=\"faktura.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . base64_encode(self::EICAR) . "\r\n"
            . "--b\r\nContent-Type: application/pdf; name=\"umowa.pdf\"\r\nContent-Disposition: attachment; filename=\"umowa.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . base64_encode('%PDF-1.4 ok') . "\r\n--b--\r\n";
    }

    private function service(bool $clam = true, bool $vt = true): MessageVirusScanService
    {
        $this->config->set('scoring.clamav_enabled', $clam);
        $this->config->set('scoring.vt_enabled', $vt);
        $this->config->set('scoring.vt_api_key', $vt ? 'k' : '');
        $clamav = $this->createMock(ClamavService::class);
        $clamav->method('scan')->willReturnCallback(fn ($data) => str_contains($data, 'EICAR') || str_contains($data, base64_encode(self::EICAR))
            ? ['clean' => false, 'signature' => 'Eicar-Test-Signature', 'error' => null]
            : ['clean' => true, 'signature' => null, 'error' => null]);
        $total = $this->createMock(VirusTotalService::class);
        $total->method('lookupHash')->willReturnCallback(fn ($hash) => $hash === hash('sha256', self::EICAR)
            ? ['found' => true, 'malicious' => 60, 'suspicious' => 0, 'total' => 70, 'error' => null]
            : ['found' => false, 'malicious' => 0, 'suspicious' => 0, 'total' => 0, 'error' => null]);
        return new MessageVirusScanService($clamav, $total, new ScoringService($this->em, $this->config));
    }

    public function testAntivirusReport()
    {
        $av = $this->service()->scan(self::raw());
        $this->assertTrue($av['infected']);
        $this->assertSame(2, $av['attachments']);
        $this->assertSame(['cała wiadomość', 'faktura.exe', 'umowa.pdf'], array_column($av['clamav']['items'], 'name'));
        $this->assertSame(['infected', 'infected', 'clean'], array_column($av['clamav']['items'], 'status'));
        $this->assertSame(['malicious', 'unknown'], array_column($av['virustotal']['items'], 'status'));
        $this->assertSame(['clamav:Eicar-Test-Signature', 'virustotal:60/70'], array_column($av['reasons'], 'rule'));

        $off = $this->service(false, false)->scan(self::raw());
        $this->assertFalse($off['infected']);
        $this->assertFalse($off['clamav']['enabled']);
        $this->assertFalse($off['virustotal']['enabled']);
        $this->assertSame([], $off['reasons']);
    }

    public function testVirusBeatsWhitelistAndComesFirst()
    {
        $this->em->persist((new Whitelist())->setEmail('jan@firma.pl')->setHost('paczki.example'));
        $this->em->flush();
        $scoring = new ScoringService($this->em, $this->config);
        $scanner = new RawMessageScanner($this->em, new HeaderAnalyzer($scoring), new DnsblService($this->em), $scoring, $this->createMock(SpamSignalService::class),
            new ImpersonationAnalyzer(), new UrlAnalyzer(), new AttachmentPolicyAnalyzer(), $this->createMock(CertHoleService::class));

        $this->assertSame('whitelisted', $scanner->scan(self::raw(), 'jan@firma.pl')['decision']);

        $av = $this->service()->scan(self::raw());
        $result = $scanner->scan(self::raw(), 'jan@firma.pl', null, ['antivirus' => $av, 'source' => 'plugin_scan']);
        $this->assertSame('spam', $result['decision']);
        $this->assertSame('clamav:Eicar-Test-Signature', $result['reasons'][0]['rule']);
        $this->assertContains('whitelist_overridden:virus', array_column($result['reasons'], 'rule'));
        $this->assertContains('source:plugin_scan', array_column($result['reasons'], 'rule'));
    }
}
