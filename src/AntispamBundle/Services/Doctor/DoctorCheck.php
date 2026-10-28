<?php

namespace AntispamBundle\Services\Doctor;

/** Result of one `antispam:doctor` check. */
final class DoctorCheck
{
    public const OK = 'ok';
    public const WARN = 'warn';
    public const FAIL = 'fail';
    public const SKIP = 'skip';

    public function __construct(
        public readonly string $id,
        public readonly string $status,
        public readonly string $message,
        /** What to do about it (empty for OK). */
        public readonly string $hint = '',
    ) {
    }

    public static function ok(string $id, string $message): self
    {
        return new self($id, self::OK, $message);
    }

    public static function warn(string $id, string $message, string $hint = ''): self
    {
        return new self($id, self::WARN, $message, $hint);
    }

    public static function fail(string $id, string $message, string $hint = ''): self
    {
        return new self($id, self::FAIL, $message, $hint);
    }

    public static function skip(string $id, string $message): self
    {
        return new self($id, self::SKIP, $message);
    }
}
