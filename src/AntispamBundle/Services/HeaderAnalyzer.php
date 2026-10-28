<?php

namespace AntispamBundle\Services;

use Ddeboer\Imap\MessageInterface;

/**
 * Analyses message headers for classic spam signals:
 *   - failed SPF, DKIM, DMARC (topmost Authentication-Results header)
 *   - missing DKIM signature / DMARC policy (weak signals, 1 point each)
 *   - suspicious From / Reply-To mismatch
 *   - presence of well-known spam markers (all-caps or "$$$" subjects, ...)
 *
 * Only the topmost Authentication-Results / Received-SPF header is read: it is
 * the one added by the receiving server. Lower ones come from earlier hops or
 * from the sender itself (a spammer can add "spf=pass" of their own) and stale
 * results of forwarded mail must not count either.
 *
 * Header heuristics are weak evidence, so their sum is capped (when the
 * scoring thresholds are known): the soft signals together stay below the
 * quarantine threshold, and the whole header score stays below the spam
 * threshold - headers alone can quarantine a message (hard SPF/DKIM/DMARC
 * failures) but never send it to SPAM. The cut appears as a negative
 * `header_cap` reason, so the reasons still add up to the score.
 *
 * Returns a score and a list of reasons that listeners can attach to the
 * running MessageEvent.
 */
class HeaderAnalyzer
{
    /** Rules that are real authentication failures; the others are soft signals. */
    const HARD_RULES = ['spf_fail', 'dkim_fail', 'dmarc_fail'];

    private $config = [
        'spf_fail'        => 6,
        'dkim_fail'       => 4,
        'dmarc_fail'      => 6,
        'dkim_none'       => 1,
        'dmarc_none'      => 1,
        'from_reply_mismatch' => 3,
        'suspicious_subject'  => 3,
        'missing_message_id'  => 2,
        'many_received_hops'  => 2,
    ];

    public function __construct(private ?ScoringService $scoring = null)
    {
    }

    public function setConfig(array $config)
    {
        $this->config = array_merge($this->config, $config);
    }

    /**
     * Analyse an IMAP message. Uses the raw header block: imap_headerinfo()
     * (getHeaders()) has no Authentication-Results, Received-SPF or Received.
     *
     * @return array ['score' => int, 'reasons' => [['rule'=>..,'score'=>..], ...]]
     */
    public function analyzeImap(MessageInterface $msg)
    {
        try {
            $raw = $msg->getRawHeaders();
        } catch (\Throwable $e) {
            $raw = '';
        }
        if (trim($raw) !== '') {
            return $this->analyzeRaw($raw);
        }

        // No raw headers: what imap_headerinfo() offers (no SPF/DKIM/DMARC).
        $headers = ['authentication-results' => '', 'received-spf' => '', 'received_count' => 0];
        try { $headers['message-id'] = (string)$msg->getId(); } catch (\Throwable $e) {}
        try { $headers['subject'] = (string)$msg->getSubject(); } catch (\Throwable $e) {}
        try {
            $from = $msg->getFrom();
            $headers['from'] = $from ? strtolower((string)$from->getAddress()) : '';
        } catch (\Throwable $e) { $headers['from'] = ''; }
        try {
            $reply = $msg->getReplyTo();
            $headers['reply-to'] = $reply ? strtolower((string)$reply[0]->getAddress()) : '';
        } catch (\Throwable $e) { $headers['reply-to'] = ''; }

        return $this->analyseHeaders($headers);
    }

    /**
     * Analyse a raw header block (plugin scanner, IMAP raw headers).
     *
     * @return array ['score' => int, 'reasons' => [...]]
     */
    public function analyzeRaw($rawHeaderBlock)
    {
        // RawMessageParser unfolds continuation lines and decodes RFC 2047 words.
        $p = new RawMessageParser(rtrim((string)$rawHeaderBlock, "\r\n") . "\r\n\r\n");
        $headers = [
            'authentication-results' => self::topmost($p->getHeaders('authentication-results')),
            'received-spf' => self::topmost($p->getHeaders('received-spf')),
            'message-id' => $p->getHeader('message-id'),
            'subject' => $p->getSubject(),
            'from' => $p->getFromAddress(),
            'reply-to' => $p->getAddress('reply-to'),
            'received_count' => count($p->getHeaders('received')),
        ];
        return $this->analyseHeaders($headers);
    }

    /** The receiving server's Authentication-Results value ('' when there is none). */
    public static function topmostAuthResults($rawHeaderBlock)
    {
        return self::topmost(RawMessageParser::headerValues($rawHeaderBlock, 'authentication-results'));
    }

    private function analyseHeaders(array $h)
    {
        $score = 0;
        $reasons = [];
        $add = function ($rule) use (&$score, &$reasons) {
            $points = (int)$this->config[$rule];
            $score += $points;
            $reasons[] = ['rule' => $rule, 'score' => $points];
        };

        $auth = strtolower($h['authentication-results'] ?? '');
        $spf = strtolower(ltrim($h['received-spf'] ?? ''));

        if (preg_match('/\bspf=(fail|softfail)\b/', $auth) || preg_match('/^(fail|softfail)\b/', $spf)) {
            $add('spf_fail');
        }
        // One good signature is enough: lists often break a second one.
        if (preg_match('/\bdkim=fail\b/', $auth) && !preg_match('/\bdkim=pass\b/', $auth)) {
            $add('dkim_fail');
        } elseif (preg_match('/\bdkim=none\b/', $auth) && !preg_match('/\bdkim=pass\b/', $auth)) {
            $add('dkim_none');
        }
        if (preg_match('/\bdmarc=fail\b/', $auth)) {
            $add('dmarc_fail');
        } elseif (preg_match('/\bdmarc=none\b/', $auth)) {
            $add('dmarc_none');
        }

        if (!empty($h['from']) && !empty($h['reply-to'])) {
            $fromDomain = self::domainOf($h['from']);
            $replyDomain = self::domainOf($h['reply-to']);
            if ($fromDomain && $replyDomain && $fromDomain !== $replyDomain) {
                $add('from_reply_mismatch');
            }
        }

        $subject = $h['subject'] ?? '';
        if ($subject !== '' && self::isSuspiciousSubject($subject)) {
            $add('suspicious_subject');
        }

        if (trim((string)($h['message-id'] ?? '')) === '') {
            $add('missing_message_id');
        }

        if (!empty($h['received_count']) && (int)$h['received_count'] > 10) {
            $add('many_received_hops');
        }

        return $this->capped($score, $reasons);
    }

    /** See the class doc: soft signals < quarantine threshold, all headers < spam threshold. */
    private function capped($score, array $reasons)
    {
        if ($this->scoring === null || $score <= 0) {
            return ['score' => $score, 'reasons' => $reasons];
        }
        $hard = 0;
        $soft = 0;
        foreach ($reasons as $r) {
            in_array($r['rule'], self::HARD_RULES, true) ? $hard += $r['score'] : $soft += $r['score'];
        }
        $capped = min($hard + min($soft, max(0, (int)$this->scoring->getQuarantineThreshold() - 1)),
                      max(0, (int)$this->scoring->getSpamThreshold() - 1));
        if ($capped < $score) {
            $reasons[] = ['rule' => 'header_cap', 'score' => $capped - $score];
            $score = $capped;
        }
        return ['score' => $score, 'reasons' => $reasons];
    }

    /**
     * All-caps (at least 10 letters and no lower-case one - "FV 2025/10/0123"
     * is not shouting), excessive punctuation, money/viagra classics.
     */
    public static function isSuspiciousSubject($subject)
    {
        $subject = mb_scrub((string)$subject, 'UTF-8');
        if ((int)preg_match_all('/\p{L}/u', $subject) >= 10 && !preg_match('/\p{Ll}/u', $subject)) return true;
        if (preg_match('/\${2,}|!{3,}|\?{3,}/', $subject)) return true;
        if (preg_match('/\b(viagra|cialis|lottery|winner|bitcoin|crypto airdrop|nigerian prince)\b/i', $subject)) return true;
        return false;
    }

    private static function topmost(array $values)
    {
        return $values ? (string)$values[0] : '';
    }

    private static function domainOf($email)
    {
        $parts = explode('@', strtolower((string)$email));
        return $parts[1] ?? '';
    }
}
