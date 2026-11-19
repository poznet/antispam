<?php

namespace AntispamBundle\Services;

/**
 * "Sprawdź tę wiadomość" from the plugins (POST /api/plugin/scan,
 * docs/thunderbird.md#check-this-message): the antivirus part, run first -
 *
 *   1. ClamAV (when configured): the whole message source, then every
 *      attachment (decoded), each up to the clamd stream limit;
 *   2. VirusTotal (when an API key is set): the SHA-256 of every attachment
 *      (only the hash leaves the server), at most MAX_VT_LOOKUPS per message.
 *
 * Runs whatever the sender (also whitelisted) and the scoring switch - it is
 * an explicit request. Never throws: an unreachable clamd / VirusTotal is
 * reported per item as "error", never as a hit.
 */
class MessageVirusScanService
{
    /** VirusTotal public API: 4 lookups a minute - more attachments are listed as "skipped". */
    public const MAX_VT_LOOKUPS = 8;

    public function __construct(
        private ClamavService $clamav,
        private VirusTotalService $virustotal,
        private ScoringService $scoring,
    ) {
    }

    /**
     * @return array{
     *   attachments: int, infected: bool, score: int, reasons: array,
     *   clamav: array{enabled: bool, items: array},
     *   virustotal: array{enabled: bool, items: array}
     * }
     */
    public function scan(string $raw): array
    {
        $attachments = [];
        try {
            $attachments = (new RawMessageParser($raw))->getParts()['attachments'] ?? [];
        } catch (\Throwable) {
        }
        $out = ['attachments' => count($attachments), 'infected' => false, 'score' => 0, 'reasons' => [],
            'clamav' => ['enabled' => false, 'items' => []], 'virustotal' => ['enabled' => false, 'items' => []]];

        // 1. ClamAV
        if ($this->scoring->isClamavEnabled()) {
            $out['clamav']['enabled'] = true;
            $dsn = $this->scoring->getClamavDsn();
            $timeout = $this->scoring->getClamavTimeout();
            $maxSize = $this->scoring->getClamavMaxSize();
            $score = $this->scoring->getClamavScore();
            $targets = [['name' => 'cała wiadomość', 'data' => $raw, 'whole' => true]];
            foreach ($attachments as $a) {
                $targets[] = ['name' => self::name($a), 'data' => (string)($a['data'] ?? ''), 'whole' => false];
            }
            foreach ($targets as $t) {
                $item = ['name' => $t['name'], 'size' => strlen($t['data']), 'status' => 'clean', 'signature' => null, 'error' => null];
                if ($t['data'] === '') {
                    $item['status'] = 'skipped';
                    $item['error'] = 'pusty';
                } elseif ($maxSize > 0 && strlen($t['data']) > $maxSize) {
                    $item['status'] = 'skipped';
                    $item['error'] = 'większy niż limit ClamAV (' . round($maxSize / 1048576, 1) . ' MB)';
                } else {
                    $r = $this->clamav->scan($t['data'], $dsn, $timeout);
                    if (!empty($r['error'])) {
                        $item['status'] = 'error';
                        $item['error'] = (string)$r['error'];
                    } elseif (!$r['clean']) {
                        $item['status'] = 'infected';
                        $item['signature'] = $r['signature'] ?: 'unknown';
                        if (!$out['infected']) {
                            $out['score'] += $score;
                            $out['reasons'][] = ['rule' => 'clamav:' . $item['signature'], 'score' => $score, 'filename' => $t['whole'] ? null : $t['name']];
                        }
                        $out['infected'] = true;
                    }
                }
                $out['clamav']['items'][] = $item;
            }
        }

        // 2. VirusTotal
        $apiKey = $this->scoring->getVirusTotalApiKey();
        if ($this->scoring->isVirusTotalEnabled() && $apiKey !== '') {
            $out['virustotal']['enabled'] = true;
            $timeout = $this->scoring->getVirusTotalTimeout();
            $threshold = $this->scoring->getVirusTotalThreshold();
            $score = $this->scoring->getVirusTotalScore();
            $lookups = 0;
            $seen = [];
            foreach ($attachments as $a) {
                $data = (string)($a['data'] ?? '');
                $hash = hash('sha256', $data);
                $item = ['name' => self::name($a), 'sha256' => $hash, 'status' => 'unknown', 'malicious' => 0, 'suspicious' => 0, 'total' => 0,
                    'link' => 'https://www.virustotal.com/gui/file/' . $hash, 'error' => null];
                if ($data === '') {
                    $item['status'] = 'skipped';
                    $item['error'] = 'pusty';
                } elseif (isset($seen[$hash])) {
                    $item = array_replace($seen[$hash], ['name' => $item['name']]);
                } elseif ($lookups >= self::MAX_VT_LOOKUPS) {
                    $item['status'] = 'skipped';
                    $item['error'] = 'limit ' . self::MAX_VT_LOOKUPS . ' zapytań na wiadomość';
                } else {
                    $lookups++;
                    $r = $this->virustotal->lookupHash($hash, $apiKey, $timeout);
                    $item['malicious'] = (int)$r['malicious'];
                    $item['suspicious'] = (int)$r['suspicious'];
                    $item['total'] = (int)$r['total'];
                    if ($r['error'] !== null) {
                        $item['status'] = 'error';
                        $item['error'] = (string)$r['error'];
                    } elseif (!$r['found']) {
                        $item['status'] = 'unknown';
                    } elseif ($r['malicious'] >= $threshold) {
                        $item['status'] = 'malicious';
                        if (!array_filter($out['reasons'], fn ($x) => str_starts_with((string)$x['rule'], 'virustotal:'))) {
                            $out['score'] += $score;
                            $out['reasons'][] = ['rule' => 'virustotal:' . $r['malicious'] . '/' . $r['total'], 'score' => $score, 'filename' => $item['name']];
                        }
                        $out['infected'] = true;
                    } elseif ($r['malicious'] > 0 || $r['suspicious'] > 0) {
                        $item['status'] = 'suspicious';
                    } else {
                        $item['status'] = 'clean';
                    }
                    $seen[$hash] = $item;
                }
                $out['virustotal']['items'][] = $item;
            }
        }

        return $out;
    }

    private static function name(array $attachment): string
    {
        $name = trim((string)($attachment['filename'] ?? ''));
        return $name !== '' ? mb_substr($name, 0, 200) : '(załącznik bez nazwy, ' . ($attachment['type'] ?? '?') . ')';
    }
}
