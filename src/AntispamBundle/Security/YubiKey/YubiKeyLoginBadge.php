<?php

namespace AntispamBundle\Security\YubiKey;

use Symfony\Component\Security\Http\Authenticator\Passport\Badge\BadgeInterface;

/**
 * Marks a passport of the passwordless YubiKey login (YubiKeyAuthenticator):
 * TwoFactorGuard treats such a login as "second factor done".
 */
final class YubiKeyLoginBadge implements BadgeInterface
{
    public function __construct(public readonly string $publicId)
    {
    }

    public function isResolved(): bool
    {
        return true;
    }
}
