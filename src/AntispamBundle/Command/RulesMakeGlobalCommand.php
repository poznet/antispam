<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\AuditLogger;
use AntispamBundle\Services\RuleGlobalizer;
use AntispamBundle\Services\RuleOwnership;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Turns the white/black list rules of one mailbox into global rules ("Wszystkie
 * skrzynki", owner '*'). Meant for installs upgraded from the single-mailbox
 * days, where every panel rule was owned by the legacy mailbox from the
 * settings and so never reached the IMAP/SSH accounts.
 *
 *     php bin/console antispam:rules:make-global --dry-run
 *     php bin/console antispam:rules:make-global [--owner=jan@firma.pl]
 *
 * A rule that already exists globally (same value and pattern type) is
 * removed instead of moved; its hit counter is added to the global one
 * (RuleGlobalizer::reassign, shared with the panel action).
 */
#[AsCommand(name: 'antispam:rules:make-global', description: 'Make the list rules of a mailbox (default: the legacy one) apply to all mailboxes')]
class RulesMakeGlobalCommand extends Command
{
    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
        private ?AuditLogger $audit = null,
        private ?RuleGlobalizer $globalizer = null,
    ) {
        parent::__construct();
        // Only reassign() is used (no per-rule audit, no jobs): the command
        // writes its own summary entry and tells the admin to sync the agents.
        $this->globalizer ??= new RuleGlobalizer($em);
    }

    protected function configure(): void
    {
        $this
            ->addOption('owner', null, InputOption::VALUE_REQUIRED, 'Mailbox whose rules become global (default: the mailbox from the "E-mail" settings)')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Only show what would change');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $owner = $input->getOption('owner') ?? $this->ownership->legacyEmail();
        if ($owner === null || trim($owner) === '' || RuleOwnership::isGlobal($owner)) {
            $output->writeln('<error>No mailbox given and no legacy mailbox in the settings - use --owner=address.</error>');
            return Command::FAILURE;
        }
        $dryRun = (bool)$input->getOption('dry-run');

        $rules = [];
        foreach (RuleGlobalizer::LISTS as [$entity]) {
            array_push($rules, ...$this->em->getRepository($entity)->findBy(['email' => $owner]));
        }
        $moved = $merged = 0;
        foreach ($this->globalizer->reassign($rules, $dryRun) as $entry) {
            $name = (new \ReflectionClass($entry['rule']))->getShortName();
            $value = RuleGlobalizer::valueOf($entry['rule']);
            if ($entry['outcome'] === RuleGlobalizer::MERGED) {
                $output->writeln(sprintf('  %s %s: already global, removing the mailbox copy', $name, $value));
                $merged++;
            } elseif ($entry['outcome'] === RuleGlobalizer::MOVED) {
                $output->writeln(sprintf('  %s %s -> global', $name, $value));
                $moved++;
            }
        }
        if (!$dryRun) {
            $this->em->flush();
            $this->audit?->log('rules.make_global', targetType: 'rules', label: sprintf('%d przeniesionych, %d scalonych', $moved, $merged), mailbox: $owner, details: ['moved' => $moved, 'merged' => $merged]);
        }

        $output->writeln(sprintf('<info>%s%d rule(s) of %s made global, %d duplicate(s) merged into existing global rules.</info>',
            $dryRun ? '[dry run] ' : '', $moved, $owner, $merged));
        if (!$dryRun && $moved + $merged > 0) {
            $output->writeln('SSH agents keep their old rules until synced: php bin/console antispam:agent:sync (or Konta -> Synchronizuj).');
        }
        return Command::SUCCESS;
    }
}
