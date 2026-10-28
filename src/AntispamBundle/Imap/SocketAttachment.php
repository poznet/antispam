<?php

namespace AntispamBundle\Imap;

/**
 * Attachment of a SocketMessage, with the accessors the pipeline uses
 * (AttachmentExtractorTrait: getFilename, getDecodedContent, getContent).
 * Not a full ddeboer AttachmentInterface: no MIME tree navigation.
 */
final class SocketAttachment
{
    public function __construct(private string $filename, private string $type, private string $data)
    {
    }

    public function getFilename(): ?string
    {
        return $this->filename !== '' ? $this->filename : null;
    }

    public function getDecodedContent(): string
    {
        return $this->data;
    }

    public function getContent(): string
    {
        return $this->data;
    }

    public function getType(): ?string
    {
        return strtok($this->type, '/') ?: null;
    }

    public function getSubtype(): ?string
    {
        $parts = explode('/', $this->type, 2);
        return isset($parts[1]) ? strtoupper($parts[1]) : null;
    }

    public function getSize(): int
    {
        return strlen($this->data);
    }

    public function isEmbeddedMessage(): bool
    {
        return false;
    }
}
