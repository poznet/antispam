<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Config;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Key/value settings stored in the `config` table (formerly the
 * "configuration" service of poznet/configbundle).
 */
class ConfigService implements RuntimeCacheInterface
{
    private $em;
    /** @var array<string, mixed> values read during this process */
    private $cache = [];

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    /**
     * @return mixed the stored value, or null when the setting was never saved
     */
    public function get($name)
    {
        if (array_key_exists($name, $this->cache)) {
            return $this->cache[$name];
        }
        $config = $this->find($name);

        return $this->cache[$name] = $config ? $config->getValue() : null;
    }

    public function set($name, $value)
    {
        $config = $this->find($name);
        if (!$config) {
            $config = (new Config())->setName($name);
            $this->em->persist($config);
        }
        $config->setValue($value);
        $this->em->flush();
        $this->cache[$name] = $value;

        return true;
    }

    private function find($name)
    {
        return $this->em->getRepository(Config::class)->findOneBy(['name' => $name]);
    }

    public function clearRuntimeCache(): void
    {
        $this->cache = [];
    }
}
