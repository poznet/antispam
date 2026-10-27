<?php

namespace AntispamBundle\Entity;

use AntispamBundle\Repository\ListSettingRepository;
use Doctrine\ORM\Mapping as ORM;

/**
 * Long, multi-line settings (protected domains, VIP names, URI block list
 * zones, blocked extensions). Config table values are capped at 255 chars, so
 * list-shaped settings live here instead.
 */
#[ORM\Entity(repositoryClass: ListSettingRepository::class)]
#[ORM\Table(name: 'antispam_list_setting')]
class ListSetting
{
    #[ORM\Column(name: 'id', type: 'integer')]
    #[ORM\Id]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private $id;

    #[ORM\Column(name: 'name', type: 'string', length: 128, unique: true)]
    private $name;

    #[ORM\Column(name: 'value', type: 'text', nullable: true)]
    private $value;

    public function getId() { return $this->id; }

    public function getName() { return $this->name; }
    public function setName($name) { $this->name = $name; return $this; }

    public function getValue() { return $this->value; }
    public function setValue($value) { $this->value = $value; return $this; }
}
