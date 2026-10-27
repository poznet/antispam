<?php

namespace AntispamBundle\Repository;

use AntispamBundle\Entity\ListSetting;
use Doctrine\ORM\EntityRepository;

class ListSettingRepository extends EntityRepository
{
    /**
     * @return string|null raw value, or null when the setting was never saved
     */
    public function getValue($name)
    {
        $row = $this->findOneBy(['name' => $name]);
        return $row ? $row->getValue() : null;
    }

    public function setValue($name, $value)
    {
        $row = $this->findOneBy(['name' => $name]);
        if (!$row) {
            $row = (new ListSetting())->setName($name);
            $this->getEntityManager()->persist($row);
        }
        $row->setValue($value);
        $this->getEntityManager()->flush();
    }
}
