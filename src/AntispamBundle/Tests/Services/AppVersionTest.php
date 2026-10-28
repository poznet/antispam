<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\AppVersion;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class AppVersionTest extends KernelTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/antispam-version-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        @unlink($this->dir . '/REVISION');
        @rmdir($this->dir);
        parent::tearDown();
    }

    public function testVersionIsSemver()
    {
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/', AppVersion::VERSION);
        $this->assertSame(AppVersion::VERSION, (new AppVersion($this->dir))->version());
    }

    public function testWithoutRevisionFileThereIsNoCommit()
    {
        $v = new AppVersion($this->dir);
        $this->assertNull($v->commit());
        $this->assertSame(AppVersion::VERSION, $v->full());
        $this->assertSame(AppVersion::VERSION, (string) $v);
    }

    public static function revisions(): array
    {
        return [
            'short hash' => ["abc1234\n", 'abc1234'],
            'full hash is shortened' => ['2051100c9e7d1f0a2b3c4d5e6f708192a3b4c5d6', '2051100'],
            'upper case' => ['ABCDEF0', 'abcdef0'],
            'build arg default' => ["unknown\n", null],
            'empty' => ['', null],
            'too short' => ['abc', null],
            'garbage / markup' => ['<script>alert(1)</script>', null],
        ];
    }

    #[DataProvider('revisions')]
    public function testRevisionFile(string $content, ?string $expected)
    {
        file_put_contents($this->dir . '/REVISION', $content);
        $v = new AppVersion($this->dir);
        $this->assertSame($expected, $v->commit());
        $this->assertSame($expected === null ? AppVersion::VERSION : AppVersion::VERSION . ' (' . $expected . ')', $v->full());
    }

    public function testExposedInContainerAndTwig()
    {
        self::bootKernel();
        $c = self::getContainer();
        $this->assertSame(AppVersion::VERSION, $c->getParameter('antispam.version'));
        $this->assertInstanceOf(AppVersion::class, $c->get(AppVersion::class));
        $globals = $c->get('twig')->getGlobals();
        $this->assertInstanceOf(AppVersion::class, $globals['antispam_version']);
    }
}
