<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\Message;

/**
 * Analyses message headers for classic spam signals:
 *   - missing / failed SPF, DKIM, DMARC (Authentication-Results header)
 *   - suspicious From / Reply-To mismatch
 *   - presence of well-known spam markers (bulk mailer IDs, cyrillic subjects, ...)
 *
 * Returns a score and a list of reasons that listeners can attach to the
 * running MessageEvent.
 */
class HeaderAnalyzer
{
    private $config = [
        'spf_fail'        => 6,
        'dkim_fail'       => 4,
        'dmarc_fail'      => 6,
        'from_reply_mismatch' => 3,
        'suspicious_subject'  => 3,
        'missing_message_id'  => 2,
        'many_received_hops'  => 2,
    ];

    public function setConfig(array $config)
    {
        $this->config = array_merge($this->config, $config);
    }

    /**
     * Analyse Ddeboer\Imap\Message headers.
     *
     * @return array ['score' => int, 'reasons' => [['rule'=>..,'score'=>..], ...]]
     */
    public function analyzeImap(Message $msg)
    {
        $headers = [];
        try {
            $auth = $msg->getHeaders()->get('authentication-results');
            if (is_array($auth)) { $auth = implode("\n", $auth); }
            $headers['authentication-results'] = (string)$auth;
        } catch (\Throwable $e) { $headers['authentication-results'] = ''; }

        try { $headers['received-spf'] = (string)$msg->getHeaders()->get('received-spf'); } catch (\Throwable $e) {}
        try { $headers['message-id'] = (string)$msg->getHeaders()->get('message-id'); } catch (\Throwable $e) {}
        try { $headers['subject'] = (string)$msg->getHeaders()->get('subject'); } catch (\Throwable $e) {}

        try {
            $from = $msg->getFrom();
            $headers['from'] = $from ? ($from->getAddress()) : '';
        } catch (\Throwable $e) { $headers['from'] = ''; }

        try {
            $reply = $msg->getReplyTo();
            $headers['reply-to'] = $reply ? ($reply[0]->getAddress() ?? '') : '';
        } catch (\Throwable $e) { $headers['reply-to'] = ''; }

        try {
            $received = $msg->getHeaders()->get('received');
            $headers['received_count'] = is_array($received) ? count($received) : ($received ? 1 : 0);
        } catch (\Throwable $e) { $headers['received_count'] = 0; }

        return $this->analyseRaw($headers);
    }

    /**
     * Analyse raw string header block (Maildir agent path).
     *
     * @return array ['score' => int, 'reasons' => [...]]
     */
    public function analyzeRaw($rawHeaderBlock)
    {
        $headers = [
            'authentication-results' => self::grabHeader($rawHeaderBlock, 'Authentication-Results', true),
            'received-spf' => self::grabHeader($rawHeaderBlock, 'Received-SPF'),
            'message-id' => self::grabHeader($rawHeaderBlock, 'Message-ID'),
            'subject' => self::grabHeader($rawHeaderBlock, 'Subject'),
            'from' => self::extractEmail(self::grabHeader($rawHeaderBlock, 'From')),
            'reply-to' => self::extractEmail(self::grabHeader($rawHeaderBlock, 'Reply-To')),
            'received_count' => preg_match_all('/^Received:/mi', $rawHeaderBlock),
        ];
        return $this->analyseRaw($headers);
    }

    private function analyseRaw(array $h)
    {
        $score = 0;
        $reasons = [];

        $auth = strtolower($h['authentication-results'] ?? '');
        $spf = strtolower($h['received-spf'] ?? '');

        if (preg_match('/spf=(fail|softfail)/', $auth) || strpos($spf, 'fail') === 0) {
            $score += $this->config['spf_fail'];
            $reasons[] = ['rule' => 'spf_fail', 'score' => $this->config['spf_fail']];
        }
        if (preg_match('/dkim=(fail|none)/', $auth)) {
            $score += $this->config['dkim_fail'];
            $reasons[] = ['rule' => 'dkim_fail', 'score' => $this->config['dkim_fail']];
        }
        if (preg_match('/dmarc=(fail|none)/', $auth)) {
            $score += $this->config['dmarc_fail'];
            $reasons[] = ['rule' => 'dmarc_fail', 'score' => $this->config['dmarc_fail']];
        }

        if (!empty($h['from']) && !empty($h['reply-to'])) {
            $fromDomain = self::domainOf($h['from']);
            $replyDomain = self::domainOf($h['reply-to']);
            if ($fromDomain && $replyDomain && $fromDomain !== $replyDomain) {
                $score += $this->config['from_reply_mismatch'];
                $reasons[] = ['rule' => 'from_reply_mismatch', 'score' => $this->config['from_reply_mismatch']];
            }
        }

        $subject = $h['subject'] ?? '';
        if ($subject && self::isSuspiciousSubject($subject)) {
            $score += $this->config['suspicious_subject'];
            $reasons[] = ['rule' => 'suspicious_subject', 'score' => $this->config['suspicious_subject']];
        }

        if (empty($h['message-id'])) {
            $score += $this->config['missing_message_id'];
            $reasons[] = ['rule' => 'missing_message_id', 'score' => $this->config['missing_message_id']];
        }

        if (!empty($h['received_count']) && (int)$h['received_count'] > 10) {
            $score += $this->config['many_received_hops'];
            $reasons[] = ['rule' => 'many_received_hops', 'score' => $this->config['many_received_hops']];
        }

        return ['score' => $score, 'reasons' => $reasons];
    }

    private static function isSuspiciousSubject($subject)
    {
        $subject = (string)$subject;
        // All-caps, excessive punctuation, money/viagra classics, non-latin scripts
        if (strlen($subject) > 8 && mb_strtoupper($subject, 'UTF-8') === $subject) return true;
        if (preg_match('/\${2,}|!{3,}|\?{3,}/', $subject)) return true;
        if (preg_match('/\b(viagra|cialis|lottery|winner|bitcoin|crypto airdrop|nigerian prince)\b/i', $subject)) return true;
        return false;
    }

    private static function grabHeader($block, $name, $multiline = false)
    {
        $flag = $multiline ? 's' : '';
        if (preg_match('/^' . preg_quote($name, '/') . ':\s*(.+?)(?:\r?\n[^\s]|$)/mi' . $flag, $block, $m)) {
            return trim($m[1]);
        }
        return '';
    }

    private static function extractEmail($line)
    {
        if (preg_match('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', (string)$line, $m)) {
            return strtolower($m[0]);
        }
        return '';
    }

    private static function domainOf($email)
    {
        $parts = explode('@', strtolower((string)$email));
        return $parts[1] ?? '';
    }
}
