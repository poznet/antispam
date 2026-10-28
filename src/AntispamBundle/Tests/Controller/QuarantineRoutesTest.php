<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\ConfigurationController;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Routing\Attribute\Route as RouteAttribute;
use Symfony\Component\Routing\Generator\UrlGenerator;
use Symfony\Component\Routing\RequestContext;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Every mailbox key QuarantineService can produce (imap, imap-<id>, ssh-<id>)
 * must be accepted by the routes that take it - otherwise the page listing
 * mailboxes fails with a 500 while generating the link.
 */
class QuarantineRoutesTest extends TestCase
{
    public function testDigestPreviewAcceptsAllMailboxKeys()
    {
        $method = new \ReflectionMethod(ConfigurationController::class, 'digestPreviewAction');
        /** @var RouteAttribute $attr */
        $attr = $method->getAttributes(RouteAttribute::class)[0]->newInstance();

        $routes = new RouteCollection();
        $routes->add('preview', new Route($attr->getPath(), [], $attr->getRequirements()));
        $generator = new UrlGenerator($routes, new RequestContext());

        foreach (['imap', 'imap-12', 'ssh-3'] as $key) {
            $this->assertSame('/digest/preview/' . $key, $generator->generate('preview', ['key' => $key]));
        }
    }
}
