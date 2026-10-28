<?php

namespace AntispamBundle\Tests\Controller;

use AntispamBundle\Controller\SpamboxController;
use AntispamBundle\Entity\SpamScoreLog;
use PHPUnit\Framework\TestCase;

class QuarantineLocateLogsTest extends TestCase
{
    private static function log($id, array $fields, array $reasons = [])
    {
        $log = (new SpamScoreLog())
            ->setAccountEmail('handel@example.com')
            ->setSender($fields['sender'] ?? 'a@shop.pl')
            ->setSubject($fields['subject'] ?? 'Oferta')
            ->setDecision(SpamScoreLog::DECISION_QUARANTINE)
            ->setReasons($reasons)
            ->setSource($fields['source'] ?? null)
            ->setOutcome($fields['outcome'] ?? null);
        (new \ReflectionProperty(SpamScoreLog::class, 'id'))->setValue($log, $id);
        return $log;
    }

    public function testLocations()
    {
        $mailboxes = [[
            'account_email' => 'Handel@example.com',
            'items' => [['from' => 'a@shop.pl', 'subject' => 'Oferta']],
        ]];
        $logs = [
            self::log(1, ['source' => SpamScoreLog::SOURCE_SCAN, 'outcome' => SpamScoreLog::OUTCOME_QUARANTINED]),
            self::log(2, ['subject' => 'Inna', 'source' => SpamScoreLog::SOURCE_SCAN, 'outcome' => SpamScoreLog::OUTCOME_QUARANTINED]),
            self::log(3, ['subject' => 'Inna', 'source' => SpamScoreLog::SOURCE_SCAN, 'outcome' => SpamScoreLog::OUTCOME_MOVE_FAILED]),
            self::log(4, ['subject' => 'Inna', 'source' => SpamScoreLog::SOURCE_PLUGIN, 'outcome' => SpamScoreLog::OUTCOME_NONE]),
            self::log(5, ['subject' => 'Inna'], [['rule' => 'source:thunderbird_plugin', 'score' => 0]]),
            self::log(6, ['subject' => 'Inna']),
        ];

        $loc = SpamboxController::locateLogs($logs, $mailboxes);

        $this->assertSame('warning', $loc[1]['class']);   // still in quarantine
        $this->assertSame('success', $loc[2]['class']);   // released / deleted
        $this->assertSame('danger', $loc[3]['class']);    // move failed
        $this->assertStringContainsString('wtyczki', $loc[4]['label']);
        $this->assertStringContainsString('wtyczki', $loc[5]['label']); // legacy plugin entry
        $this->assertStringContainsString('sprzed', $loc[6]['label']);
    }
}
