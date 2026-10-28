<?php

namespace AntispamBundle\Services;

/**
 * The SSH server presented a host key other than the one pinned on the
 * account (see SshService::authenticate()).
 */
class HostKeyMismatchException extends \RuntimeException
{
}
