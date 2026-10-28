<?php

namespace AntispamBundle\Controller;

use AntispamBundle\Services\AuditLogger;

/**
 * One-line audit calls for AbstractController subclasses:
 *
 *     $this->audit('rule.add', targetType: 'whitelist', targetId: $id, label: $host, mailbox: $owner);
 *
 * The logger comes from the controller's service locator (subscribed lazily,
 * so constructors and existing unit tests stay unchanged); a controller wired
 * without it (unit tests with a hand-made locator or no container at all)
 * simply does not audit.
 */
trait AuditTrait
{
    public static function getSubscribedServices(): array
    {
        return parent::getSubscribedServices() + [AuditLogger::class => '?' . AuditLogger::class];
    }

    protected function audit(string $action, mixed ...$args): void
    {
        $this->auditLogger()?->log($action, ...$args);
    }

    protected function auditLogger(): ?AuditLogger
    {
        return isset($this->container) && $this->container->has(AuditLogger::class) ? $this->container->get(AuditLogger::class) : null;
    }
}
