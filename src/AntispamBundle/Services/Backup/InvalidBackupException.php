<?php

namespace AntispamBundle\Services\Backup;

/** The backup file is unreadable, not a backup, or of an unsupported schema version. */
class InvalidBackupException extends \RuntimeException
{
}
