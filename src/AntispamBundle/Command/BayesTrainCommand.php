<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\Bayes\BayesService;
use AntispamBundle\Services\Bayes\BayesTokenizer;
use AntispamBundle\Services\ConnectionService;
use AntispamBundle\Services\ImapScanService;
use Ddeboer\Imap\ConnectionInterface;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Bootstraps the Bayes classifier from an IMAP mailbox: the newest --limit
 * messages of --folder are learned as spam, those of --ham-folder as ham.
 * Messages are only read (BODY.PEEK - flags are not changed), never moved.
 * Works while the classifier is switched off, so it can be trained before
 * scoring is enabled. SSH+Maildir accounts are not supported (the panel has
 * no access to their mail files).
 *
 *     php bin/console antispam:bayes:train --account=jan@firma.pl --folder=SPAM --ham-folder=INBOX --limit=500
 */
#[AsCommand(name: 'antispam:bayes:train', description: 'Train the local Bayes classifier from IMAP folders (spam / ham)')]
class BayesTrainCommand extends Command
{
    public const MAX_LIMIT = 5000;

    public function __construct(
        private BayesService $bayes,
        private EntityManagerInterface $em,
        private ImapScanService $imapScan,
        private ConnectionService $legacy,
        private ?AuditLogger $audit = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('account', null, InputOption::VALUE_REQUIRED, 'IMAP account (id or e-mail); omit with --legacy')
            ->addOption('legacy', null, InputOption::VALUE_NONE, 'Use the mailbox from the "E-mail" settings')
            ->addOption('folder', null, InputOption::VALUE_REQUIRED, 'Folder learned as spam (empty = none)', 'SPAM')
            ->addOption('ham-folder', null, InputOption::VALUE_REQUIRED, 'Folder learned as ham (empty = none)', '')
            ->addOption('limit', null, InputOption::VALUE_REQUIRED, 'Newest messages per folder (max ' . self::MAX_LIMIT . ')', '500');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $limit = (int)$input->getOption('limit');
        if ($limit < 1 || $limit > self::MAX_LIMIT) {
            $output->writeln('<error>--limit must be 1-' . self::MAX_LIMIT . '</error>');
            return Command::INVALID;
        }
        $folders = array_filter(['spam' => trim((string)$input->getOption('folder')), 'ham' => trim((string)$input->getOption('ham-folder'))], fn($f) => $f !== '');
        if (!$folders) {
            $output->writeln('<error>Give --folder and/or --ham-folder</error>');
            return Command::INVALID;
        }

        try {
            [$connection, $mailbox] = $this->open($input);
        } catch (\Throwable $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return Command::FAILURE;
        }

        $summary = [];
        foreach ($folders as $verdict => $name) {
            if (!$connection->hasMailbox($name)) {
                $output->writeln(sprintf('<error>Folder "%s" not found</error>', $name));
                return Command::FAILURE;
            }
            $summary[$verdict] = $this->trainFolder($connection, $name, $verdict, $mailbox, $limit, $output);
        }

        $stats = $this->bayes->stats();
        $output->writeln(sprintf('Database: %d spam / %d ham messages, %d tokens (global). Scoring %s (needs %d spam + %d ham)%s.',
            $stats['spam'], $stats['ham'], $stats['tokens'], $stats['ready'] ? 'ready' : 'not ready yet', $stats['min_spam'], $stats['min_ham'],
            $this->bayes->isEnabled() ? '' : ', classifier switched off in Ustawienia → Filtr spamu'));
        $this->audit?->log('bayes.trained', targetType: 'bayes', label: implode(', ', array_map(fn($v, $f) => $f . '=' . $v, array_keys($folders), $folders)),
            mailbox: $mailbox, details: $summary + ['source' => 'command']);

        return Command::SUCCESS;
    }

    /** @return array{learned:int, skipped:int, failed:int} */
    private function trainFolder(ConnectionInterface $connection, string $name, string $verdict, ?string $mailbox, int $limit, OutputInterface $output): array
    {
        $folder = $connection->getMailbox($name);
        $uids = array_map('intval', $folder->getMessages()->getArrayCopy());
        rsort($uids, SORT_NUMERIC);
        $out = ['learned' => 0, 'skipped' => 0, 'failed' => 0];
        foreach (array_slice($uids, 0, $limit) as $uid) {
            try {
                $msg = $folder->getMessage($uid);
                if ((int)$msg->getSize() > BayesService::MAX_TRAIN_BYTES) {
                    $out['skipped']++;
                    continue;
                }
                $r = $this->bayes->learnFields(BayesTokenizer::fieldsFromImap($msg), $verdict, $mailbox, 'command');
                $out[$r['learned'] ? 'learned' : 'skipped']++;
            } catch (\Throwable $e) {
                $out['failed']++;
            }
        }
        $output->writeln(sprintf('%s (%s): %d learned, %d skipped (duplicate / empty / too large), %d failed of %d newest.',
            $name, $verdict, $out['learned'], $out['skipped'], $out['failed'], min($limit, count($uids))));
        return $out;
    }

    /** @return array{0: ConnectionInterface, 1: ?string} connection, mailbox e-mail */
    private function open(InputInterface $input): array
    {
        if ($input->getOption('legacy')) {
            return [$this->legacy->getConnection(), null];
        }
        $ref = trim((string)$input->getOption('account'));
        if ($ref === '') {
            throw new \InvalidArgumentException('Give --account=<id|e-mail> or --legacy');
        }
        $repo = $this->em->getRepository(Account::class);
        $account = ctype_digit($ref) ? $repo->find((int)$ref) : $repo->findOneBy(['email' => $ref], ['id' => 'ASC']);
        if (!$account instanceof Account) {
            throw new \InvalidArgumentException('Account not found: ' . $ref);
        }
        if (!$account->isImap()) {
            throw new \InvalidArgumentException('Only IMAP accounts can be used (SSH+Maildir mail is not readable from the panel)');
        }
        return [$this->imapScan->connect($account), (string)$account->getEmail()];
    }
}
