<?php

namespace AntispamBundle\Command;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
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
 * removed instead of moved; its hit counter is added to the global one.
 */
#[AsCommand(name: 'antispam:rules:make-global', description: 'Make the list rules of a mailbox (default: the legacy one) apply to all mailboxes')]
class RulesMakeGlobalCommand extends Command
{
    /** entity => field holding the rule value */
    const LISTS = [
        Whitelist::class => 'host',
        Blacklist::class => 'host',
        EmailWhitelist::class => 'whitelistemail',
        EmailBlacklist::class => 'blacklistemail',
    ];

    public function __construct(
        private EntityManagerInterface $em,
        private RuleOwnership $ownership,
    ) {
        parent::__construct();
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

        $moved = $merged = 0;
        foreach (self::LISTS as $entity => $field) {
            $getter = 'get' . ucfirst($field);
            $repo = $this->em->getRepository($entity);
            foreach ($repo->findBy(['email' => $owner]) as $rule) {
                $global = $repo->findOneBy([
                    'email' => RuleOwnership::ALL,
                    $field => $rule->$getter(),
                    'patternType' => $rule->getPatternType(),
                ]);
                $name = (new \ReflectionClass($entity))->getShortName();
                if ($global) {
                    $output->writeln(sprintf('  %s %s: already global, removing the mailbox copy', $name, $rule->$getter()));
                    if (!$dryRun) {
                        $global->setCounter((int)$global->getCounter() + (int)$rule->getCounter());
                        $this->em->remove($rule);
                    }
                    $merged++;
                } else {
                    $output->writeln(sprintf('  %s %s -> global', $name, $rule->$getter()));
                    if (!$dryRun) {
                        $rule->setEmail(RuleOwnership::ALL);
                    }
                    $moved++;
                }
            }
        }
        if (!$dryRun) {
            $this->em->flush();
        }

        $output->writeln(sprintf('<info>%s%d rule(s) of %s made global, %d duplicate(s) merged into existing global rules.</info>',
            $dryRun ? '[dry run] ' : '', $moved, $owner, $merged));
        if (!$dryRun && $moved + $merged > 0) {
            $output->writeln('SSH agents keep their old rules until synced: php bin/console antispam:agent:sync (or Konta -> Synchronizuj).');
        }
        return Command::SUCCESS;
    }
}
