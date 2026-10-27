<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\SshService;
use PHPUnit\Framework\TestCase;

class SshServiceTest extends TestCase
{
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
}
