<?php

namespace AntispamBundle\Command;

use AntispamBundle\Services\PluginService;
use AntispamBundle\Services\ThunderbirdPluginBuilder;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Builds the Thunderbird .xpi to a file (docs/plugin-distribution.md):
 * --generic for addons.thunderbird.net, otherwise the instance build with
 * --server or plugin.public_url. bin/build-thunderbird-xpi does the same
 * without booting Symfony (CI).
 */
#[AsCommand(name: 'antispam:plugin:build', description: 'Build the Thunderbird plugin .xpi (generic or for this instance)')]
class PluginBuildCommand extends Command
{
    public function __construct(
        private ThunderbirdPluginBuilder $builder,
        private PluginService $plugin,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('generic', null, InputOption::VALUE_NONE, 'No server URL / update_url (package for addons.thunderbird.net)')
            ->addOption('server', null, InputOption::VALUE_REQUIRED, 'Server URL to bake in (default: plugin.public_url)')
            ->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Output file (default: build/antispam-thunderbird-<version>[-instance].xpi)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $server = null;
        if ($input->getOption('generic')) {
            if ($input->getOption('server')) {
                $output->writeln('<error>--generic and --server are exclusive</error>');
                return Command::INVALID;
            }
        } else {
            $server = rtrim((string)($input->getOption('server') ?: $this->plugin->getPublicUrl()), '/');
            $p = $server === '' ? false : parse_url($server);
            if (!$p || !in_array($p['scheme'] ?? '', ['http', 'https'], true) || empty($p['host'])) {
                $output->writeln('<error>Give --generic, or --server=https://... (or set plugin.public_url)</error>');
                return Command::INVALID;
            }
        }

        $version = $this->builder->version();
        $file = $input->getOption('output')
            ?: $this->projectDir . '/build/antispam-thunderbird-' . $version . ($server === null ? '' : '-instance') . '.xpi';
        if (!is_dir(dirname($file)) && !@mkdir(dirname($file), 0775, true)) {
            $output->writeln('<error>Cannot create ' . dirname($file) . '</error>');
            return Command::FAILURE;
        }
        $this->builder->build($server, $file);
        $output->writeln($file);
        $output->writeln(sprintf('version %s, %s build, sha256 %s', $version,
            $server === null ? 'generic' : 'instance (' . $server . ')', hash_file('sha256', $file)));
        return Command::SUCCESS;
    }
}
