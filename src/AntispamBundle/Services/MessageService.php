<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\MessageInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Remembers which IMAP messages were already checked (one marker file per
 * message id in var/data/checked).
 */
class MessageService
{
    private $dir;
    private $fs;

    public function __construct(#[Autowire('%kernel.project_dir%/var/data/checked')] string $dir)
    {
        $this->dir = $dir;
        $this->fs = new Filesystem();
    }

    /**
     * Marks the message as checked (creates its marker file).
     */
    public function setAsChecked(MessageInterface $msg)
    {
        $name = $this->path($msg->getId());
        if (!$this->fs->exists($name)) {
            $this->fs->dumpFile($name, (string)$msg->getNumber());
        }
    }

    public function isChecked(MessageInterface $msg)
    {
        return $this->fs->exists($this->path($msg->getId()));
    }

    /**
     * Forgets the message (removes its marker file).
     */
    public function unCheck(MessageInterface $msg)
    {
        $this->fs->remove($this->path($msg->getId()));
    }

    /**
     * Forgets all messages (removes every marker file).
     */
    public function unCheckAll()
    {
        $this->fs->remove($this->dir);
    }

    private function path($id)
    {
        // Message-ID headers may contain "/" - keep the marker inside the dir.
        return $this->dir . '/' . str_replace(['/', '\\'], '_', (string)$id);
    }
}
