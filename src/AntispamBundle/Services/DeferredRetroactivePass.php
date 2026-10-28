<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\EmailBlacklist;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Event\TerminateEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Runs the retroactive pass for rules learned from plugin reports
 * (RetroactiveSpamService::applyRule - an IMAP/SSH login plus moving mail)
 * after the response has been sent, so the plugin does not wait for the
 * mailbox and does not run into its request timeout.
 *
 * Production runs Apache + mod_php, which has no fastcgi_finish_request():
 * the client only sees the end of the response early when it can tell where
 * the body ends. So a response with deferred work gets an explicit
 * Content-Length, "Connection: close" and no mod_deflate (which would drop
 * the length and hold the body until the script ends). Response::send() then
 * flushes the body before kernel.terminate runs. Under PHP-FPM
 * fastcgi_finish_request() closes the request on its own.
 */
class DeferredRetroactivePass implements EventSubscriberInterface, ResetInterface
{
    /** @var array<int, true> EmailBlacklist ids */
    private array $pending = [];

    public function __construct(
        private EntityManagerInterface $em,
        private RetroactiveSpamService $retroactive,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // Last, after ResponseListener::prepare() and anything else touching the body.
            KernelEvents::RESPONSE => ['onResponse', -1024],
            KernelEvents::TERMINATE => 'onTerminate',
        ];
    }

    /** Apply the rule to mail already in the mailbox once the response is out. */
    public function defer(EmailBlacklist $rule): void
    {
        if ($rule->getId() !== null) {
            $this->pending[(int)$rule->getId()] = true;
        }
    }

    public function hasPending(): bool
    {
        return $this->pending !== [];
    }

    public function onResponse(ResponseEvent $event): void
    {
        if (!$this->pending || !$event->isMainRequest()) {
            return;
        }
        self::prepareEarlyClose($event->getResponse());
    }

    /** Headers that let the client finish reading the response before the script ends. */
    public static function prepareEarlyClose(Response $response): void
    {
        $content = $response->getContent();
        if ($content === false) {
            return; // streamed / binary file - length unknown here
        }
        $response->headers->remove('Transfer-Encoding');
        $response->headers->set('Content-Length', (string)strlen($content));
        $response->headers->set('Connection', 'close');
        if (\function_exists('apache_setenv')) {
            // mod_deflate: compressing would replace Content-Length with chunked encoding.
            @apache_setenv('no-gzip', '1');
        }
    }

    public function onTerminate(TerminateEvent $event): void
    {
        $this->runPending();
    }

    /** @return int number of rules processed */
    public function runPending(): int
    {
        if (!$this->pending) {
            return 0;
        }
        $ids = array_keys($this->pending);
        $this->pending = [];

        // The response is already out: neither the client going away nor a
        // slow mailbox may cut the pass short / hang the worker forever.
        // Under mod_php max_execution_time would otherwise kill the pass half
        // way; every IMAP step is bounded by the c-client timeouts instead
        // and the pass by RetroactiveSpamService's candidate/move caps.
        ignore_user_abort(true);
        @set_time_limit(0);
        ImapScanService::applyImapTimeouts();

        $done = 0;
        foreach ($ids as $id) {
            try {
                if (!$this->em->isOpen()) {
                    break;
                }
                $rule = $this->em->find(EmailBlacklist::class, $id);
                if (!$rule) {
                    continue;
                }
                $result = $this->retroactive->applyRule($rule);
                $done++;
                if ($this->logger) {
                    $this->logger->info('antispam: retroactive pass after plugin report', [
                        'owner' => $rule->getEmail(), 'sender' => $rule->getBlacklistemail(),
                        'moved' => $result['moved'], 'errors' => $result['errors'], 'skipped' => $result['skipped'],
                    ]);
                }
            } catch (\Throwable $e) {
                if ($this->logger) {
                    $this->logger->error('antispam: retroactive pass after plugin report failed', ['rule' => $id, 'exception' => $e]);
                }
            }
        }
        return $done;
    }

    public function reset(): void
    {
        $this->pending = [];
    }
}
