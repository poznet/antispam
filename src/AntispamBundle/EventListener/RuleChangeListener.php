<?php

namespace AntispamBundle\EventListener;

use AntispamBundle\Entity\Blacklist;
use AntispamBundle\Entity\EmailBlacklist;
use AntispamBundle\Entity\EmailWhitelist;
use AntispamBundle\Entity\Whitelist;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\Event\LifecycleEventArgs;

class RuleChangeListener
{
    private $em;
    private $ruleEntityClasses = [
        Whitelist::class,
        EmailWhitelist::class,
        Blacklist::class,
        EmailBlacklist::class,
    ];

    public function __construct(EntityManagerInterface $em)
    {
        $this->em = $em;
    }

    public function postPersist(LifecycleEventArgs $args)
    {
        $this->markAccountsForSync($args);
    }

    public function postUpdate(LifecycleEventArgs $args)
    {
        $this->markAccountsForSync($args);
    }

    public function postRemove(LifecycleEventArgs $args)
    {
        $this->markAccountsForSync($args);
    }

    private function markAccountsForSync(LifecycleEventArgs $args)
    {
        $entity = $args->getObject();

        $isRuleEntity = false;
        foreach ($this->ruleEntityClasses as $class) {
            if ($entity instanceof $class) {
                $isRuleEntity = true;
                break;
            }
        }

        if (!$isRuleEntity) {
            return;
        }

        $email = $entity->getEmail();
        $accounts = $this->em->getRepository('AntispamBundle:Account')->findBy([
            'email' => $email,
            'connectionType' => 'ssh',
        ]);

        foreach ($accounts as $account) {
            $account->setNeedsSync(true);
        }

        // Flush happens in the calling context
    }
}
