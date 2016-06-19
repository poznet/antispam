<?php
/**
 * Created by PhpStorm.
 * User: joseph
 * Date: 19.06.16
 * Time: 22:04
 */

namespace AntispamBundle\Tests\Service;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

class InboxServiceTest extends KernelTestCase
{
    private $container;

    public function setUp()
    {
        self::bootKernel();

        $this->container = self::$kernel->getContainer();
    }


    public function testSpamboxName(){
        $inbox=$this->container->get('antispam.inbox');
        $this->AssertEquals('SPAM',$inbox->getSpamFolderName());
    }


}