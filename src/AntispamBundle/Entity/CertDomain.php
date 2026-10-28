<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * One domain of the CERT Polska "Lista Ostrzeżeń" (hole.cert.pl). The table is
 * filled in bulk by CertHoleService::sync() with plain DBAL statements - never
 * through the ORM - and always holds lower-case ASCII (punycode) names.
 */
#[ORM\Entity]
#[ORM\Table(name: 'antispam_cert_domain')]
class CertDomain

{
    #[ORM\Id]
    #[ORM\Column(name: 'domain', type: 'string', length: 255)]
    private $domain;

    public function getDomain() { return $this->domain; }
}
