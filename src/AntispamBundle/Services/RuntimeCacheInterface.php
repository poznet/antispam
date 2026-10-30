<?php

namespace AntispamBundle\Services;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/**
 * A service that keeps rules / settings read from the database for the
 * lifetime of the process (fine for one web request or one console run).
 * The long-running job worker (antispam:jobs:work) clears them before every
 * job, so a rule or setting changed in the panel applies to the next job -
 * not only after the worker restarts.
 *
 * Deliberately not Symfony's ResetInterface / kernel.reset: BayesService
 * already has a reset() that wipes the learned tokens.
 */
#[AutoconfigureTag('antispam.runtime_cache')]
interface RuntimeCacheInterface
{
    public function clearRuntimeCache(): void;
}
