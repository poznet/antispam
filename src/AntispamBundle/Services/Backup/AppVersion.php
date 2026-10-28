<?php

namespace AntispamBundle\Services\Backup;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * Application version for the backup envelope and `antispam:doctor`, read
 * defensively: the first of the container parameters `app.version` /
 * `antispam.version`, a `VERSION` file in the project root, or null when the
 * install has none. Never throws.
 */
class AppVersion
{
    public const PARAMETERS = ['app.version', 'antispam.version'];

    public function __construct(
        private ParameterBagInterface $parameters,
        #[Autowire('%kernel.project_dir%')] private string $projectDir,
    ) {
    }

    public function get(): ?string
    {
        foreach (self::PARAMETERS as $name) {
            try {
                if ($this->parameters->has($name)) {
                    $value = $this->parameters->get($name);
                    if (is_scalar($value) && trim((string)$value) !== '') {
                        return trim((string)$value);
                    }
                }
            } catch (\Throwable) {
                // an env() placeholder that cannot be resolved - try the next source
            }
        }
        $file = $this->projectDir . '/VERSION';
        if (is_file($file) && is_readable($file)) {
            $value = trim((string)file_get_contents($file, false, null, 0, 64));
            if ($value !== '' && preg_match('/^[\w.+-]+$/', $value)) {
                return $value;
            }
        }

        return null;
    }
}
