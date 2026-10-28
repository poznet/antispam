<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Entity\Account;
use AntispamBundle\Services\Bayes\BayesService;
use AntispamBundle\Services\Bayes\BayesStore;
use AntispamBundle\Services\ConfigService;
use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use PHPUnit\Framework\TestCase;

/** In-memory SQLite schema + a Bayes service and a tiny corpus. */
abstract class BayesTestCase extends TestCase
{
    protected EntityManager $em;
    protected ConfigService $config;

    protected function setUp(): void
    {
        $config = ORMSetup::createAttributeMetadataConfiguration([dirname(__DIR__, 3) . '/Entity'], true);
        $this->em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($this->em))->createSchema($this->em->getMetadataFactory()->getAllMetadata());
        $this->config = new ConfigService($this->em);
        $this->config->set('bayes.enabled', true);
        $this->config->set('bayes.min_spam', 5);
        $this->config->set('bayes.min_ham', 5);
    }

    protected function bayes(): BayesService
    {
        return new BayesService(new BayesStore($this->em->getConnection()), $this->config, $this->em);
    }

    protected function account(string $email): Account
    {
        $a = (new Account())->setName($email)->setEmail($email)->setConnectionType(Account::CONNECTION_IMAP)
            ->setImapHost('imap.example')->setImapPort(993)->setImapLogin($email)->setImapPassword('x');
        $this->em->persist($a);
        $this->em->flush();
        return $a;
    }

    protected static function raw(string $subject, string $body, string $from = 'a@example.com', string $id = ''): string
    {
        $id = $id !== '' ? $id : '<' . sha1($subject . $body) . '@' . substr(strrchr($from, '@'), 1) . '>';
        return "From: Nadawca <{$from}>\r\nTo: jan@firma.pl\r\nSubject: {$subject}\r\nMessage-ID: {$id}\r\n"
            . "Content-Type: text/plain; charset=utf-8\r\n\r\n{$body}\r\n";
    }

    /** @return string[] raw spam messages */
    protected static function spamCorpus(int $n = 6): array
    {
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[] = self::raw("Wygrana nagroda {$i}", "Gratulacje! Odbierz darmową nagrodę, tani kredyt bez BIK, kliknij https://promo-{$i}.casino-win.ru/odbierz teraz. Viagra cialis promocja.", "lotto{$i}@casino-win.ru");
        }
        return $out;
    }

    /** @return string[] raw ham messages */
    protected static function hamCorpus(int $n = 6): array
    {
        $out = [];
        for ($i = 0; $i < $n; $i++) {
            $out[] = self::raw("Spotkanie projektowe {$i}", "Cześć, w załączniku raport kwartalny i faktura. Spotkanie w sprawie projektu przesuwamy na czwartek. Pozdrawiam, Anna", "anna{$i}@firma.pl");
        }
        return $out;
    }

    protected function train(BayesService $bayes, ?string $mailbox = null): void
    {
        foreach (self::spamCorpus() as $raw) {
            $bayes->learnRaw($raw, 'spam', $mailbox, 'test');
        }
        foreach (self::hamCorpus() as $raw) {
            $bayes->learnRaw($raw, 'ham', $mailbox, 'test');
        }
    }
}
