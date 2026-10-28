<?php

namespace AntispamBundle\Tests\Services\Backup;

use AntispamBundle\Entity\Account;

/** Per-mailbox settings (Ustawienia skrzynki) survive export / import. */
class MailboxSettingsBackupTest extends BackupTestCase
{
    private static function seedOverrides($em): void
    {
        self::seed($em);
        $jan = $em->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $jan->setSpamThreshold(6)->setQuarantineThreshold(3)->setScoringEnabled(false)
            ->setDigestEnabled(true)->setDigestRecipient('kierownik@firma.pl')->setDigestHour(14)
            ->setAutoRescan(true)->setRescanWeekday(3)->setRescanHour(1);
        $em->flush();
        $em->clear();
    }

    public function testRoundTripKeepsOverridesAndInheritance()
    {
        $source = self::em();
        self::seedOverrides($source);
        $data = self::roundTrip(self::exporter($source)->export(false));

        $exported = array_column($data['accounts'], null, 'email');
        $this->assertSame(6, $exported['jan@firma.pl']['spam_threshold']);
        $this->assertSame('kierownik@firma.pl', $exported['jan@firma.pl']['digest_recipient']);
        $this->assertNull($exported['ssh@firma.pl']['spam_threshold']);

        $target = self::em();
        $report = self::importer($target)->import($data, ['accounts']);
        $target->clear();
        $this->assertSame([], array_values(array_filter($report->getWarnings(), fn ($w) => str_contains($w, 'setting ignored'))));

        $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertSame(
            ['spam_threshold' => 6, 'quarantine_threshold' => 3, 'scoring_enabled' => false, 'digest_enabled' => true, 'digest_recipient' => 'kierownik@firma.pl', 'digest_hour' => 14],
            $jan->getSettingsOverrides()
        );
        $this->assertSame([true, 3, 1], [$jan->getAutoRescan(), $jan->getRescanWeekday(), $jan->getRescanHour()], 'weekly rescan schedule');
        $ssh = $target->getRepository(Account::class)->findOneBy(['email' => 'ssh@firma.pl']);
        $this->assertSame([], $ssh->getSettingsOverrides());
        $this->assertSame([false, null, null], [$ssh->getAutoRescan(), $ssh->getRescanWeekday(), $ssh->getRescanHour()]);
    }

    public function testOlderBackupWithoutTheFieldsKeepsCurrentOverrides()
    {
        $em = self::em();
        self::seedOverrides($em);
        $data = self::roundTrip(self::exporter($em)->export(false));
        foreach ($data['accounts'] as &$item) {
            foreach (['spam_threshold', 'quarantine_threshold', 'scoring_enabled', 'digest_enabled', 'digest_recipient', 'digest_hour'] as $f) {
                unset($item[$f]);
            }
        }
        unset($item);

        self::importer($em)->import($data, ['accounts']); // merge
        $em->clear();

        $jan = $em->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertSame(6, $jan->getSpamThreshold());
        $this->assertSame(14, $jan->getDigestHour());
    }

    public function testInvalidValuesAreDroppedWithAWarning()
    {
        $source = self::em();
        self::seedOverrides($source);
        $data = self::roundTrip(self::exporter($source)->export(false));
        foreach ($data['accounts'] as &$item) {
            if ($item['email'] === 'jan@firma.pl') {
                $item['digest_hour'] = 31;
                $item['quarantine_threshold'] = 9; // >= spam threshold 6
                $item['digest_recipient'] = 'not an e-mail';
            }
        }
        unset($item);

        $target = self::em();
        $report = self::importer($target)->import($data, ['accounts']);
        $target->clear();

        $this->assertCount(3, array_filter($report->getWarnings(), fn ($w) => str_contains($w, 'setting ignored')));
        $jan = $target->getRepository(Account::class)->findOneBy(['email' => 'jan@firma.pl']);
        $this->assertNull($jan->getDigestHour());
        $this->assertNull($jan->getDigestRecipient());
        $this->assertNull($jan->getQuarantineThreshold());
        $this->assertNull($jan->getSpamThreshold());
        $this->assertFalse($jan->getScoringEnabled());
    }
}
