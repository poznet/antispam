<?php

namespace AntispamBundle\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Routing\RouterInterface;

/**
 * Every mailbox key QuarantineService can produce (imap, imap-<id>, ssh-<id>)
 * must be accepted by the routes that take it - otherwise the page listing
 * mailboxes fails with a 500 while generating the link.
 */
class QuarantineRoutesTest extends KernelTestCase
{
    public function testDigestPreviewAcceptsAllMailboxKeys()
    {
        self::bootKernel();
        /** @var RouterInterface $router */
        $router = self::getContainer()->get('router');

        foreach (['imap', 'imap-12', 'ssh-3'] as $key) {
            $this->assertSame('/config/digest/preview/' . $key, $router->generate('antispam_digest_preview', ['key' => $key]));
        }
    }
}
