<?php

namespace AntispamBundle\Tests\Services;

use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Services\DeferredRetroactivePass;
use AntispamBundle\Services\RetroactiveSpamService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * The retroactive pass of a plugin report (IMAP/SSH login + moving mail) runs
 * after the response, and the response is marked so that Apache + mod_php
 * lets the client finish reading it before the pass ends.
 */
class DeferredRetroactivePassTest extends TestCase
{
    private function rule(int $id): EmailBlacklist
    {
        $rule = (new EmailBlacklist())->setEmail('jan@example.com')->setBlacklistemail('spam@evil.top');
        $prop = new \ReflectionProperty(EmailBlacklist::class, 'id');
        $prop->setValue($rule, $id);
        return $rule;
    }

    private function responseEvent(Response $response, int $type = HttpKernelInterface::MAIN_REQUEST): ResponseEvent
    {
        return new ResponseEvent($this->createMock(HttpKernelInterface::class), new Request(), $type, $response);
    }

    public function testSubscribesToResponseAndTerminate()
    {
        $events = DeferredRetroactivePass::getSubscribedEvents();
        $this->assertArrayHasKey(KernelEvents::RESPONSE, $events);
        $this->assertArrayHasKey(KernelEvents::TERMINATE, $events);
        // After ResponseListener (priority 0), which may still change the response.
        $this->assertLessThan(0, $events[KernelEvents::RESPONSE][1]);
    }

    public function testResponseWithPendingPassGetsLengthAndConnectionClose()
    {
        $retro = $this->createMock(RetroactiveSpamService::class);
        $retro->expects($this->never())->method('applyRule');
        $pass = new DeferredRetroactivePass($this->createMock(EntityManagerInterface::class), $retro);
        $pass->defer($this->rule(5));

        $response = new JsonResponse(['verdict' => 'spam', 'retroactive' => 'scheduled']);
        $response->headers->set('Transfer-Encoding', 'chunked');
        $pass->onResponse($this->responseEvent($response));

        $this->assertSame((string)strlen($response->getContent()), $response->headers->get('Content-Length'));
        $this->assertSame('close', $response->headers->get('Connection'));
        $this->assertFalse($response->headers->has('Transfer-Encoding'));
    }

    public function testResponseWithoutPendingPassIsUntouched()
    {
        $pass = new DeferredRetroactivePass($this->createMock(EntityManagerInterface::class), $this->createMock(RetroactiveSpamService::class));
        $response = new JsonResponse(['ok' => true]);
        $pass->onResponse($this->responseEvent($response));
        $this->assertFalse($response->headers->has('Content-Length'));
        $this->assertFalse($response->headers->has('Connection'));

        // Sub-requests never get the headers.
        $pass->defer($this->rule(1));
        $sub = new JsonResponse(['ok' => true]);
        $pass->onResponse($this->responseEvent($sub, HttpKernelInterface::SUB_REQUEST));
        $this->assertFalse($sub->headers->has('Connection'));
    }

    public function testTerminateAppliesEachRuleOnceAndSurvivesErrors()
    {
        $r1 = $this->rule(1);
        $r2 = $this->rule(2);
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('isOpen')->willReturn(true);
        $em->method('find')->willReturnCallback(fn ($class, $id) => [1 => $r1, 2 => $r2][$id] ?? null);

        $retro = $this->createMock(RetroactiveSpamService::class);
        $seen = [];
        $retro->expects($this->exactly(2))->method('applyRule')->willReturnCallback(function ($rule) use (&$seen) {
            $seen[] = $rule->getId();
            if ($rule->getId() === 1) {
                throw new \RuntimeException('IMAP timeout');
            }
            return ['moved' => 3, 'errors' => [], 'skipped' => null];
        });

        $pass = new DeferredRetroactivePass($em, $retro);
        $pass->defer($r1);
        $pass->defer($r1); // same rule twice in one request
        $pass->defer($r2);
        $this->assertTrue($pass->hasPending());

        $pass->onTerminate(new TerminateEvent($this->createMock(HttpKernelInterface::class), new Request(), new Response()));
        $this->assertSame([1, 2], $seen);
        $this->assertFalse($pass->hasPending());

        // Nothing left for a second terminate (e.g. a worker reused for the next request).
        $this->assertSame(0, $pass->runPending());
    }

    public function testRuleDeletedMeanwhileIsSkipped()
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('isOpen')->willReturn(true);
        $em->method('find')->willReturn(null);
        $retro = $this->createMock(RetroactiveSpamService::class);
        $retro->expects($this->never())->method('applyRule');

        $pass = new DeferredRetroactivePass($em, $retro);
        $pass->defer($this->rule(9));
        $this->assertSame(0, $pass->runPending());
    }

    public function testResetDropsPendingWork()
    {
        $pass = new DeferredRetroactivePass($this->createMock(EntityManagerInterface::class), $this->createMock(RetroactiveSpamService::class));
        $pass->defer($this->rule(3));
        $pass->reset();
        $this->assertFalse($pass->hasPending());
    }
}
