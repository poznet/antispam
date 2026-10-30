<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\ConfigService;
use AntispamBundle\Services\HostKeyMismatchException;
use AntispamBundle\Services\MailboxSettingsResolver;
use AntispamBundle\Services\ScoringService;
use AntispamBundle\Services\SshService;
use Doctrine\ORM\EntityManagerInterface;
use phpseclib3\Net\SFTP;
use phpseclib3\Net\SSH2;
use PHPUnit\Framework\TestCase;

class SshServiceTest extends TestCase
{
    private const HOST_KEY_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

    private $keysDir;

    protected function setUp(): void
    {
        $this->keysDir = sys_get_temp_dir() . '/antispam-keys-' . bin2hex(random_bytes(4));
        mkdir($this->keysDir);
        // Any parsable private key will do: login() is mocked.
        file_put_contents($this->keysDir . '/id_test', \phpseclib3\Crypt\EC::createKey('Ed25519')->toString('OpenSSH'));
    }

    protected function tearDown(): void
    {
        @unlink($this->keysDir . '/id_test');
        @rmdir($this->keysDir);
    }

    public function testShellPathQuotesAndKeepsHomeExpansion()
    {
        $this->assertSame('"$HOME"/\'Maildir\'', SshService::shellPath('~/Maildir'));
        $this->assertSame('"$HOME"', SshService::shellPath('~'));
        $this->assertSame("'/home/a b/Maildir'", SshService::shellPath('/home/a b/Maildir'));
        $this->assertSame("'x; rm -rf / #'", SshService::shellPath('x; rm -rf / #'));
        $this->assertSame("'~user/x'", SshService::shellPath('~user/x'));

        $home = sys_get_temp_dir();
        $out = shell_exec('HOME=' . escapeshellarg($home) . ' sh -c ' . escapeshellarg('printf %s --maildir=' . SshService::shellPath('~/a b')));
        $this->assertSame('--maildir=' . $home . '/a b', $out);
    }

    public function testKeyMustLiveInKeysDirectory()
    {
        $dir = sys_get_temp_dir() . '/antispam-keys-' . bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir . '/id_test', 'not a key');
        $outside = tempnam(sys_get_temp_dir(), 'outside');

        $ssh = new SshService($dir);
        $load = new \ReflectionMethod($ssh, 'loadKeyMaterial');

        try {
            $this->assertSame('not a key', $load->invoke($ssh, (new Account())->setSshKeyPath('id_test')));
            $this->assertSame('not a key', $load->invoke($ssh, (new Account())->setSshKeyPath($dir . '/id_test')));

            foreach ([$outside, $dir . '/../' . basename($outside), '/etc/passwd'] as $path) {
                try {
                    $load->invoke($ssh, (new Account())->setSshKeyPath($path));
                    $this->fail('accepted ' . $path);
                } catch (\RuntimeException $e) {
                    $this->assertStringContainsString('keys directory', $e->getMessage());
                }
            }
        } finally {
            unlink($dir . '/id_test');
            rmdir($dir);
            unlink($outside);
        }
    }

    public function testAgentCommandCarriesAccountIdAfterTheCommand()
    {
        $ssh = new SshService($this->keysDir);
        $account = $this->account();
        $this->assertSame(
            'php "$HOME"/\'antispam-agent/antispam-agent.php\' scan --maildir=x --account=5',
            $ssh->buildAgentCommand($account, 'scan', '--maildir=x')
        );
        $this->assertSame("php '/opt/a/antispam-agent.php' test", $ssh->buildAgentCommand((new Account())->setAgentPath('/opt/a/'), 'test'));
    }

    public function testResolveRemotePathExpandsTildeAgainstSftpHome()
    {
        $this->assertSame('/home/u/antispam-agent/antispam-agent.php', SshService::resolveRemotePath('~/antispam-agent/antispam-agent.php', '/home/u'));
        $this->assertSame('/home/u', SshService::resolveRemotePath('~', '/home/u/'));
        $this->assertSame('/home/u/agent/x', SshService::resolveRemotePath('agent/x', '/home/u'));
        $this->assertSame('/opt/agent/x', SshService::resolveRemotePath('/opt/agent/x', false));

        $this->expectException(\RuntimeException::class);
        SshService::resolveRemotePath('~/x', false);
    }

    public function testFingerprintMatchesOpenSsh()
    {
        // ssh-keygen -lf: SHA256 of the decoded key blob, unpadded base64
        $expected = 'SHA256:' . rtrim(base64_encode(hash('sha256', base64_decode(self::HOST_KEY_BLOB), true)), '=');
        $this->assertSame($expected, SshService::fingerprint('ssh-ed25519 ' . self::HOST_KEY_BLOB));
        $this->assertStringNotContainsString('=', SshService::fingerprint('ssh-ed25519 ' . self::HOST_KEY_BLOB));
    }

    public function testDecodeAgentJsonToleratesNoiseBeforeTheDocument()
    {
        $this->assertSame(['success' => true], SshService::decodeAgentJson("{\"success\": true}\n"));
        $this->assertSame(['total' => 3], SshService::decodeAgentJson("PHP Warning: x in y on line 3\n{\n  \"total\": 3\n}\n"));
        $this->assertNull(SshService::decodeAgentJson('{"total": 3'));
        $this->assertNull(SshService::decodeAgentJson(''));
    }

    public function testInterpretReportsTimeoutsOldAgentsAndGarbage()
    {
        $ssh = new SshService($this->keysDir);

        $r = $ssh->interpret('scan', ['output' => '{"total": 1', 'stderr' => '', 'exit' => false, 'timeout' => true], 3600);
        $this->assertFalse($r['success']);
        $this->assertTrue($r['timeout']);
        $this->assertStringContainsString('3600 s', $r['error']);

        $usage = "Antispam Maildir Agent\nUsage:\n  php antispam-agent.php test\n";
        $r = $ssh->interpret('quarantine-list', ['output' => $usage, 'stderr' => '', 'exit' => 0, 'timeout' => false], 60);
        $this->assertFalse($r['success']);
        $this->assertStringContainsString('wdróż go ponownie', $r['error']);
        $this->assertStringContainsString('quarantine-list', $r['error']);

        $r = $ssh->interpret('scan', ['output' => '', 'stderr' => 'Could not open input file: /home/u/antispam-agent/antispam-agent.php', 'exit' => 1, 'timeout' => false], 60);
        $this->assertStringContainsString('Nie znaleziono agenta', $r['error']);

        $r = $ssh->interpret('scan', ['output' => '', 'stderr' => 'sh: php: command not found', 'exit' => 127, 'timeout' => false], 60);
        $this->assertStringContainsString('Brak PHP CLI', $r['error']);

        $r = $ssh->interpret('scan', ['output' => 'garbage', 'stderr' => '', 'exit' => 255, 'timeout' => false], 60);
        $this->assertStringContainsString('kod wyjścia 255', $r['error']);

        // A JSON answer without agent_version comes from an agent older than 3.0.
        $r = $ssh->interpret('import-rules', ['output' => '{"success":true,"imported":{}}', 'stderr' => '', 'exit' => 0, 'timeout' => false], 60);
        $this->assertTrue($r['success']);
        $this->assertTrue($r['agent_outdated']);
        $this->assertStringContainsString('Wdróż', $r['agent_warning']);

        $r = $ssh->interpret('health', ['output' => json_encode(['success' => true, 'agent_version' => SshService::bundledAgentVersion()]), 'stderr' => '', 'exit' => 0, 'timeout' => false], 60);
        $this->assertArrayNotHasKey('agent_outdated', $r);
    }

    public function testBundledAgentVersionIsReadFromTheScript()
    {
        $this->assertMatchesRegularExpression('/^\d+\.\d+/', (string)SshService::bundledAgentVersion());
    }

    public function testHostKeyIsPinnedOnFirstLoginAndEnforcedLater()
    {
        $account = $this->account();
        $ssh = $this->service([$this->sshMock('{"success":true,"agent_version":"9.9"}')]);
        $ssh->runHealth($account);
        $pinned = SshService::fingerprint('ssh-ed25519 ' . self::HOST_KEY_BLOB);
        $this->assertSame($pinned, $account->getSshHostKey());

        $account->setSshHostKey('SHA256:somethingElse');
        $mock = $this->sshMock('{}');
        $mock->expects($this->never())->method('login');
        try {
            $this->service([$mock])->runHealth($account);
            $this->fail('changed host key accepted');
        } catch (HostKeyMismatchException $e) {
            $this->assertStringContainsString('SHA256:somethingElse', $e->getMessage());
            $this->assertStringContainsString($pinned, $e->getMessage());
        }
    }

    public function testHostKeyWithInvalidSignatureIsRefused()
    {
        $mock = $this->createMock(SSH2::class);
        $mock->method('getServerPublicHostKey')->willReturn(false);
        $mock->expects($this->never())->method('login');
        $this->expectException(\RuntimeException::class);
        $this->service([$mock])->runHealth($this->account());
    }

    public function testCommandsGetTimeoutsAndStderrStaysOutOfTheJson()
    {
        $mock = $this->sshMock(null, 'PHP Warning: noise');
        $mock->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['scan']);
        $mock->expects($this->once())->method('enableQuietMode');
        $mock->expects($this->once())->method('exec')->with($this->callback(function ($cmd) {
            return str_contains($cmd, " scan --maildir='/srv/mail/Maildir' --spam-threshold=12 --quarantine-threshold=6 --no-dnsbl --account=5");
        }))->willReturn('{"total":2,"agent_version":"9.9"}');

        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnMap([
            ['scoring.spam_threshold', '12'],
            ['scoring.quarantine_threshold', '6'],
            ['scoring.dnsbl_enabled', '0'],
        ]);
        $scoring = new ScoringService($this->createMock(EntityManagerInterface::class), $config);
        $ssh = $this->service([$mock], $scoring);

        $this->assertSame(2, $ssh->runScan($this->account())['total']);
    }

    public function testRescanCarriesTheScanOptionsTimeLimitAndReset()
    {
        $first = $this->sshMock(null);
        $first->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['rescan']);
        $first->expects($this->once())->method('exec')->with($this->callback(fn($cmd) => str_contains($cmd, " rescan --maildir='/srv/mail/Maildir' --time-limit=110 --reset --account=5")))
            ->willReturn('{"success":true,"rescan":true,"total":2,"remaining":1,"agent_version":"9.9"}');
        $this->assertSame(1, $this->service([$first])->runRescan($this->account(), true, 110)['remaining']);

        $next = $this->sshMock(null);
        $next->expects($this->once())->method('exec')->with($this->callback(fn($cmd) => str_contains($cmd, ' rescan ') && str_contains($cmd, '--time-limit=10 --account=5') && !str_contains($cmd, '--reset')))
            ->willReturn('{"success":true,"rescan":true,"total":2,"remaining":0,"agent_version":"9.9"}');
        $this->assertSame(0, $this->service([$next])->runRescan($this->account(), false, 3)['remaining'], 'at least 10 s');
    }

    public function testAgentScriptHasTheRescanCommand()
    {
        $this->assertSame('3.6', SshService::bundledAgentVersion());
        $src = file_get_contents(__DIR__ . '/../../Resources/agent/antispam-agent.php');
        $this->assertStringContainsString("case 'rescan':", $src);
        $this->assertStringContainsString("case 'quarantine-purge':", $src);
    }

    public function testQuarantinePurgePassesOnlyAKnownModeAndUsesItsTimeout()
    {
        $purge = $this->sshMock(null);
        $purge->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['quarantine-purge']);
        $purge->expects($this->once())->method('exec')->with($this->callback(fn($cmd) => str_contains($cmd, " quarantine-purge --maildir='/srv/mail/Maildir' --mode=high_risk --account=5")))
            ->willReturn('{"success":true,"total":3,"deleted":2,"skipped":1,"failed":0,"agent_version":"9.9"}');
        $this->assertSame(2, $this->service([$purge])->quarantinePurge($this->account(), 'high_risk')['deleted']);

        $this->expectException(\InvalidArgumentException::class);
        $this->service([])->quarantinePurge($this->account(), "all; rm -rf ~");
    }

    public function testSpamFolderCommandsQuoteTheIdAndUseTheirTimeouts()
    {
        $list = $this->sshMock(null);
        $list->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['spam-list']);
        $list->expects($this->once())->method('exec')->with($this->callback(fn($cmd) => str_contains($cmd, " spam-list --maildir='/srv/mail/Maildir' --limit=100 --account=5")))
            ->willReturn('{"success":true,"total":0,"items":[],"agent_version":"9.9"}');
        $this->assertTrue($this->service([$list])->spamList($this->account(), 100)['success']);

        $release = $this->sshMock(null);
        $release->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['spam-release']);
        $release->expects($this->once())->method('exec')->with($this->callback(fn($cmd) => str_contains($cmd, " spam-release --maildir='/srv/mail/Maildir' --id=''\\''x; rm -rf ~'\\''' --whitelist --account=5")))
            ->willReturn('{"success":true,"sender":"a@b.pl","agent_version":"9.9"}');
        $this->assertSame('a@b.pl', $this->service([$release])->spamRelease($this->account(), "'x; rm -rf ~'", true)['sender']);
    }

    public function testOldAgentWithoutSpamCommandsGetsADeployHint()
    {
        $ssh = $this->service([$this->sshMock("Antispam Maildir Agent 3.0\nUsage:\n  php antispam-agent.php test\n")]);
        $res = $ssh->spamList($this->account());
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('nie obsługuje polecenia "spam-list"', $res['error']);
    }

    public function testScoringOffDisablesEveryHeuristicForOldAgents()
    {
        $mock = $this->sshMock(null);
        $mock->expects($this->once())->method('exec')->with($this->callback(function ($cmd) {
            return str_contains($cmd, '--no-dnsbl --no-headers --no-impersonation --no-urls --no-cert --no-attachment-policy --no-clamav --no-virustotal');
        }))->willReturn('{"total":0}');
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnMap([['scoring.enabled', '0']]);
        $scoring = new ScoringService($this->createMock(EntityManagerInterface::class), $config);

        $this->service([$mock], $scoring)->runScan($this->account());
    }

    public function testScanFlagsUseTheAccountSettings()
    {
        $mock = $this->sshMock(null);
        $mock->expects($this->once())->method('exec')->with($this->callback(function ($cmd) {
            return str_contains($cmd, " scan --maildir='/srv/mail/Maildir' --spam-threshold=7 --quarantine-threshold=6 --no-dnsbl --no-headers --no-impersonation");
        }))->willReturn('{"total":0}');
        $config = $this->createMock(ConfigService::class);
        $config->method('get')->willReturnMap([
            ['scoring.spam_threshold', '12'],
            ['scoring.quarantine_threshold', '6'],
        ]);
        $em = $this->createMock(EntityManagerInterface::class);
        $scoring = new ScoringService($em, $config);
        $account = $this->account()->setSpamThreshold(7)->setScoringEnabled(false);

        $this->service([$mock], $scoring, new MailboxSettingsResolver($scoring, $config, $em))->runScan($account);
        $this->assertSame(12, $scoring->getSpamThreshold());
    }

    public function testDeployResolvesTildeAndReportsTheSelfTest()
    {
        $sftp = $this->sftpMock();
        $sftp->expects($this->exactly(2))->method('put')->willReturnCallback(function ($path, $data) {
            $this->assertSame('/home/u/antispam-agent/antispam-agent.php', $path);
            return true;
        });
        $sftp->method('stat')->willReturn(['size' => filesize(__DIR__ . '/../../Resources/agent/antispam-agent.php')]);
        $ssh = $this->sshMock(null);
        $ssh->expects($this->once())->method('exec')->with($this->callback(function ($cmd) {
            return str_contains($cmd, "antispam-agent.php' test --maildir='/srv/mail/Maildir' --account=5");
        }))->willReturn('{"success":true,"checks":{},"agent_version":"3.0"}');

        $res = $this->service([$sftp, $ssh])->deployAgent($this->account());
        $this->assertTrue($res['success']);
        $this->assertSame('/home/u/antispam-agent/antispam-agent.php', $res['remote_path']);
    }

    public function testDeployFailsWhenTheSelfTestFails()
    {
        $sftp = $this->sftpMock();
        $sftp->method('put')->willReturn(true);
        $sftp->method('stat')->willReturn(['size' => filesize(__DIR__ . '/../../Resources/agent/antispam-agent.php')]);
        $ssh = $this->sshMock('{"success":false,"errors":["PHP extension mbstring is required"],"agent_version":"3.0"}');

        $res = $this->service([$sftp, $ssh])->deployAgent($this->account());
        $this->assertFalse($res['success']);
        $this->assertStringContainsString('mbstring', $res['error']);
    }

    public function testDeployFailsWhenTheUploadFails()
    {
        $sftp = $this->sftpMock();
        $sftp->method('put')->willReturn(false);
        $sftp->method('getLastSFTPError')->willReturn('NET_SFTP_STATUS_PERMISSION_DENIED');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('PERMISSION_DENIED');
        $this->service([$sftp])->deployAgent($this->account());
    }

    public function testSyncUploadsTheRulesFileAndFeedsItOnStdin()
    {
        $json = json_encode(['blacklist' => [['email' => 'a', 'host' => "x\\n'y", 'pattern_type' => 'regex', 'score' => 10]], 'settings' => ['url_dbl_zones' => "a 1\nb 2"]]);
        $uploaded = [];
        $sftp = $this->sftpMock();
        $sftp->method('put')->willReturnCallback(function ($path, $data) use (&$uploaded) {
            $uploaded[$path] = $data;
            return true;
        });
        $sftp->method('stat')->willReturn(['size' => strlen($json)]);
        $sftp->expects($this->atLeastOnce())->method('chmod')->with(0600, $this->anything());

        $ssh = $this->sshMock(null);
        $ssh->expects($this->once())->method('setTimeout')->with(SshService::TIMEOUTS['import-rules']);
        $ssh->expects($this->once())->method('exec')->willReturnCallback(function ($cmd) use (&$uploaded) {
            $path = array_key_last($uploaded);
            $this->assertMatchesRegularExpression('#^/home/u/antispam-agent/\.rules-import-[0-9a-f]{12}\.json$#', $path);
            $this->assertStringContainsString(" import-rules --account=5 < '" . $path . "'; rc=\$?; rm -f '" . $path . "'; exit \$rc", $cmd);
            $this->assertStringNotContainsString('echo', $cmd);
            return '{"success":true,"imported":{"blacklist":1},"agent_version":"9.9"}';
        });

        $res = $this->service([$sftp, $ssh])->syncRules($this->account(), $json);
        $this->assertTrue($res['success']);
        $this->assertSame($json, end($uploaded));
    }

    private function account()
    {
        $account = (new Account())
            ->setConnectionType(Account::CONNECTION_SSH)
            ->setSshHost('mail.example.test')
            ->setSshUser('u')
            ->setSshKeyPath('id_test')
            ->setMaildirPath('/srv/mail/Maildir')
            ->setAgentPath('~/antispam-agent');
        (new \ReflectionProperty(Account::class, 'id'))->setValue($account, 5);
        return $account;
    }

    private function sshMock($output, $stderr = '')
    {
        $mock = $this->createMock(SSH2::class);
        $this->primeConnection($mock);
        if ($output !== null) {
            $mock->method('exec')->willReturn($output);
        }
        $mock->method('getStdError')->willReturn($stderr);
        $mock->method('getExitStatus')->willReturn(0);
        $mock->method('isTimeout')->willReturn(false);
        return $mock;
    }

    private function sftpMock()
    {
        $mock = $this->createMock(SFTP::class);
        $this->primeConnection($mock);
        $mock->method('pwd')->willReturn('/home/u');
        $mock->method('is_dir')->willReturn(true);
        $mock->method('chmod')->willReturn(true);
        return $mock;
    }

    private function primeConnection($mock)
    {
        $mock->method('getServerPublicHostKey')->willReturn('ssh-ed25519 ' . self::HOST_KEY_BLOB);
        $mock->method('login')->willReturn(true);
    }

    /**
     * SshService whose connections come from $sessions in order (SFTP mocks
     * for createSftp, SSH2 mocks for createSsh).
     */
    private function service(array $sessions, ?ScoringService $scoring = null, ?MailboxSettingsResolver $resolver = null)
    {
        return new class($this->keysDir, $sessions, $scoring, $resolver) extends SshService {
            private $sessions;

            public function __construct($dir, array $sessions, $scoring, $resolver)
            {
                parent::__construct($dir, $scoring, null, $resolver);
                $this->sessions = $sessions;
            }

            protected function createSsh(Account $account)
            {
                return $this->next(false);
            }

            protected function createSftp(Account $account)
            {
                return $this->next(true);
            }

            private function next($sftp)
            {
                foreach ($this->sessions as $i => $s) {
                    if (($s instanceof SFTP) === $sftp) {
                        unset($this->sessions[$i]);
                        return $s;
                    }
                }
                throw new \LogicException('no ' . ($sftp ? 'SFTP' : 'SSH') . ' session left');
            }
        };
    }
}
