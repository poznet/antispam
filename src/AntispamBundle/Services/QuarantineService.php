<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\EmailWhitelist;
use Doctrine\ORM\EntityManagerInterface;
use Poznet\ConfigBundle\Service\ConfigService;
use Psr\Container\ContainerInterface;

/**
 * One API over both quarantine back-ends:
 *
 *   - "imap"        the legacy single IMAP mailbox (QUARANTINE folder)
 *   - "ssh-<id>"    an SSH+Maildir account, handled through the agent
 *
 * Used by the quarantine digest and its one-click release / whitelist /
 * delete links. IMAP services are pulled lazily from a service locator
 * because ConnectionService logs in to IMAP as soon as it is built.
 */
class QuarantineService
{
    const IMAP_KEY = 'imap';
    const NOT_FOUND = 'Nie znaleziono wiadomości w kwarantannie (została już dostarczona lub usunięta?).';

    private $em;
    private $config;
    private $ssh;
    private $imap;

    public function __construct(EntityManagerInterface $em, ConfigService $config, SshService $ssh, ContainerInterface $imap)
    {
        $this->em = $em;
        $this->config = $config;
        $this->ssh = $ssh;
        $this->imap = $imap;
    }

    /**
     * Every mailbox that has a quarantine, with the address its digest goes to.
     *
     * @return array list of ['key', 'label', 'account_email', 'recipient']
     */
    public function getMailboxes()
    {
        $out = [];
        if ($this->config->get('imap') && $this->config->get('login')) {
            $email = (string)$this->config->get('email');
            $recipient = trim((string)$this->config->get('digest.imap_recipient')) ?: $email;
            $out[] = ['key' => self::IMAP_KEY, 'label' => 'IMAP: ' . ($email ?: $this->config->get('login')), 'account_email' => $email, 'recipient' => $recipient];
        }
        foreach ($this->em->getRepository('AntispamBundle:Account')->findBy(['connectionType' => Account::CONNECTION_SSH]) as $account) {
            if (!$account->getAgentDeployed()) {
                continue;
            }
            $out[] = [
                'key' => 'ssh-' . $account->getId(),
                'label' => $account->getName() . ' (' . $account->getEmail() . ')',
                'account_email' => $account->getEmail(),
                'recipient' => $account->getEmail(),
            ];
        }
        return $out;
    }

    public function getMailbox($key)
    {
        foreach ($this->getMailboxes() as $m) {
            if ($m['key'] === $key) {
                return $m;
            }
        }
        return null;
    }

    /**
     * @param \DateTimeInterface|null $since only messages received after this moment
     *
     * @return array list of ['id','from','from_name','subject','date' => \DateTimeImmutable|null,'score','reasons']
     */
    public function listItems($key, ?\DateTimeInterface $since = null, $limit = 200)
    {
        if ($key === self::IMAP_KEY) {
            return $this->listImap($since, $limit);
        }
        $account = $this->sshAccount($key);
        $res = $this->ssh->quarantineList($account, $since ? $since->getTimestamp() : null, $limit);
        if (empty($res['success'])) {
            throw new \RuntimeException('Agent quarantine-list failed: ' . substr((string)($res['error'] ?? 'unknown error'), 0, 300));
        }
        $items = [];
        foreach ((array)$res['items'] as $row) {
            $items[] = [
                'id' => (string)$row['id'],
                'from' => (string)($row['from'] ?? ''),
                'from_name' => (string)($row['from_name'] ?? ''),
                'subject' => (string)($row['subject'] ?? ''),
                'date' => !empty($row['date']) ? new \DateTimeImmutable($row['date']) : null,
                'score' => isset($row['score']) ? $row['score'] : null,
                'reasons' => (array)($row['reasons'] ?? []),
            ];
        }
        return $items;
    }

    /**
     * Move a message back to the inbox, optionally whitelisting its sender.
     *
     * @return array ['success' => bool, 'message' => string, 'sender' => string]
     */
    public function release($key, $id, $whitelist = false)
    {
        $mailbox = $this->getMailbox($key);
        if (!$mailbox) {
            return ['success' => false, 'message' => 'Ta skrzynka nie jest już obsługiwana.', 'sender' => ''];
        }

        if ($key === self::IMAP_KEY) {
            try {
                $connection = $this->imap->get('antispam.connection')->getConnection();
                $msg = $connection->getMailbox($this->imap->get('antispam.inbox')->getQuarantineFolderName())->getMessage((int)$id);
                $sender = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : '';
                // Released mail must not be quarantined again on the next scan.
                $this->imap->get('antispam.message')->setAsChecked($msg);
                $msg->move($connection->getMailbox('INBOX'));
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
        } else {
            $res = $this->ssh->quarantineAction($this->sshAccount($key), 'release', $id, $whitelist);
            if (empty($res['success'])) {
                return ['success' => false, 'message' => self::agentError($res, 'Nie udało się dostarczyć wiadomości.'), 'sender' => ''];
            }
            $sender = strtolower((string)($res['sender'] ?? ''));
        }

        if ($whitelist && $sender !== '') {
            $this->whitelistSender($mailbox['account_email'], $sender);
        }

        return [
            'success' => true,
            'message' => $whitelist && $sender !== ''
                ? sprintf('Wiadomość została dostarczona do skrzynki odbiorczej. Poczta od %s nie będzie już filtrowana.', $sender)
                : 'Wiadomość została dostarczona do skrzynki odbiorczej.',
            'sender' => $sender,
        ];
    }

    /**
     * @return array ['success' => bool, 'message' => string, 'sender' => string]
     */
    public function delete($key, $id)
    {
        if (!$this->getMailbox($key)) {
            return ['success' => false, 'message' => 'Ta skrzynka nie jest już obsługiwana.', 'sender' => ''];
        }
        if ($key === self::IMAP_KEY) {
            try {
                $connection = $this->imap->get('antispam.connection')->getConnection();
                $msg = $connection->getMailbox($this->imap->get('antispam.inbox')->getQuarantineFolderName())->getMessage((int)$id);
                $sender = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : '';
                $msg->delete();
                $connection->expunge();
            } catch (\Throwable $e) {
                return ['success' => false, 'message' => self::NOT_FOUND, 'sender' => ''];
            }
            return ['success' => true, 'message' => 'Wiadomość została usunięta.', 'sender' => $sender];
        }

        $res = $this->ssh->quarantineAction($this->sshAccount($key), 'delete', $id);
        if (empty($res['success'])) {
            return ['success' => false, 'message' => self::agentError($res, 'Nie udało się usunąć wiadomości.'), 'sender' => ''];
        }
        return ['success' => true, 'message' => 'Wiadomość została usunięta.', 'sender' => (string)($res['sender'] ?? '')];
    }

    /**
     * Add an exact e-mail whitelist rule for $sender on $accountEmail (no-op
     * when one already exists).
     */
    public function whitelistSender($accountEmail, $sender)
    {
        $repo = $this->em->getRepository('AntispamBundle:EmailWhitelist');
        if ($repo->findOneBy(['email' => $accountEmail, 'whitelistemail' => $sender])) {
            return false;
        }
        $rule = new EmailWhitelist();
        $rule->setEmail($accountEmail)
            ->setWhitelistemail($sender)
            ->setPatternType(EmailWhitelist::PATTERN_EXACT);
        $this->em->persist($rule);
        $this->em->flush();
        return true;
    }

    private function listImap(?\DateTimeInterface $since = null, $limit = 200)
    {
        $inbox = $this->imap->get('antispam.inbox');
        $items = [];
        foreach ($inbox->getInbox($inbox->getQuarantineFolderName()) as $msg) {
            try {
                $date = $msg->getDate();
                if ($since && $date && $date < $since) {
                    continue;
                }
                $from = $msg->getFrom();
                $items[] = [
                    'id' => (string)$msg->getNumber(),
                    'from' => $from ? strtolower((string)$from->getAddress()) : '',
                    'from_name' => $from ? (string)$from->getName() : '',
                    'subject' => (string)$msg->getSubject(),
                    'date' => $date,
                    'score' => null,
                    'reasons' => [],
                ];
            } catch (\Throwable $e) {
                continue;
            }
        }
        usort($items, function ($a, $b) {
            return ($b['date'] ? $b['date']->getTimestamp() : 0) - ($a['date'] ? $a['date']->getTimestamp() : 0);
        });
        return array_slice($this->attachImapScores($items), 0, $limit);
    }

    /**
     * IMAP quarantine has no stable link to the score log, so match the most
     * recent quarantine decision with the same sender + subject.
     */
    private function attachImapScores(array $items)
    {
        $repo = $this->em->getRepository('AntispamBundle:SpamScoreLog');
        foreach ($items as &$item) {
            $log = $repo->findOneBy(
                ['sender' => $item['from'], 'subject' => mb_substr($item['subject'], 0, 500, 'UTF-8'), 'decision' => 'quarantine'],
                ['scoredAt' => 'DESC']
            );
            if ($log) {
                $item['score'] = $log->getScore();
                $item['reasons'] = $log->getReasonsDecoded();
            }
        }
        return $items;
    }

    /**
     * End-user message for a failed agent call. Raw agent output (paths, PHP
     * errors) is never shown on the public page.
     */
    private static function agentError(array $res, $fallback)
    {
        if (stripos((string)($res['error'] ?? ''), 'not found') !== false) {
            return self::NOT_FOUND;
        }
        return $fallback;
    }

    private function sshAccount($key)
    {
        if (!preg_match('/^ssh-(\d+)$/', (string)$key, $m)) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        $account = $this->em->getRepository('AntispamBundle:Account')->find((int)$m[1]);
        if (!$account || !$account->isSsh()) {
            throw new \InvalidArgumentException('Unknown mailbox: ' . $key);
        }
        return $account;
    }
}
