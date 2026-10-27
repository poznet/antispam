<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * Key/value application setting (formerly poznet/configbundle). Values are
 * stored PHP-serialized in the `config` table, so existing installs keep
 * their settings.
 */
#[ORM\Entity]
#[ORM\Table(name: 'config')]
class Config
{
    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'name', type: 'string', length: 255)]
    private $name;

    #[ORM\Column(name: 'value', type: 'string', length: 255)]
    private $value;

    /** Unused, kept so schema updates don't drop the legacy column. */
    #[ORM\Column(name: 'forobject', type: 'string', length: 255, nullable: true)]
    private $for;

    public function getId() { return $this->id; }

    public function getName() { return $this->name; }
    public function setName($name) { $this->name = $name; return $this; }

    public function getValue()
    {
        return unserialize((string)$this->value, ['allowed_classes' => false]);
    }

    public function setValue($value)
    {
        $this->value = serialize($value);
        return $this;
    }
}
