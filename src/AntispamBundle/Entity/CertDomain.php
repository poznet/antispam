<?php

namespace AntispamBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * One domain of the CERT Polska "Lista Ostrzeżeń" (hole.cert.pl). The table is
 * filled in bulk by CertHoleService::sync() with plain DBAL statements - never
 * through the ORM - and always holds lower-case ASCII (punycode) names.
 *
 * The column is ASCII (CertHoleService::normalizeDomain() only lets through
 * [a-z0-9._-], at most 253 chars), so the primary key is 253 bytes instead of
 * 1020 bytes of utf8mb4 - within the 767-byte limit of old InnoDB row formats.
 */
#[ORM\Entity]
#[ORM\Table(name: 'antispam_cert_domain')]
class CertDomain

{
    #[ORM\Id]
    #[ORM\Column(name: 'domain', type: 'string', length: 253, options: ['charset' => 'ascii'])]
    private $domain;

    public function getDomain() { return $this->domain; }
}
