<?php

namespace AntispamBundle\Services\Bayes;

use AntispamBundle\Services\RawMessageParser;
use Ddeboer\Imap\MessageInterface;

/**
 * Turns a message into the set of tokens the naive Bayes classifier learns
 * and scores (SpamBayes / Graham "A Plan for Spam" style):
 *
 *   - subject words ("subject:<word>") and body words (text part, else the
 *     stripped HTML part), lower-cased, Polish diacritics kept;
 *   - link hosts ("url:<host>", "url:<last two labels>"), URLs are removed
 *     from the text before the words are split;
 *   - a few header clues: From / Reply-To / Message-ID domains, X-Mailer
 *     (digits collapsed), the top-level content type.
 *
 * Each token counts once per message; at most MAX_TOKENS per message, words
 * shorter than 3 characters and pure numbers are dropped, words longer than
 * MAX_WORD become a "skip:<first char>:<length/10*10>" token.
 *
 * Only hash() of a token is ever stored (first 8 bytes of SHA-1), never the
 * word. The standalone Maildir agent has an exact copy (bayesTokenize() in
 * antispam-agent.php, PHP 7.1) - AgentParityTest keeps them equal.
 */
final class BayesTokenizer
{
    public const MAX_TOKENS = 1000;
    public const MAX_WORD = 20;
    public const MIN_WORD = 3;
    /** Bytes of body text looked at. */
    public const MAX_BODY_BYTES = 102400;

    /**
     * @param array{subject?:string, from?:string, reply_to?:string, message_id?:string, x_mailer?:string, content_type?:string, text?:string, html?:string} $f
     *
     * @return string[] unique tokens in insertion order
     */
    public static function tokenize(array $f): array
    {
        $tokens = [];
        $add = static function (string $t) use (&$tokens): void {
            if (count($tokens) < self::MAX_TOKENS) {
                $tokens[$t] = true;
            }
        };

        foreach (self::words((string)($f['subject'] ?? '')) as $w) {
            $add('subject:' . $w);
        }

        $from = self::domain((string)($f['from'] ?? ''));
        $add('from:' . ($from !== '' ? $from : 'none'));
        $reply = self::domain((string)($f['reply_to'] ?? ''));
        if ($reply !== '') {
            $add('replyto:' . $reply);
            if ($reply !== $from) {
                $add('replyto:differs');
            }
        }
        if (preg_match('/@([^@>\s]+)>?\s*$/', (string)($f['message_id'] ?? ''), $m)) {
            $add('msgid:' . strtolower($m[1]));
        } else {
            $add('msgid:none');
        }
        $mailer = trim(mb_strtolower(self::utf8((string)($f['x_mailer'] ?? '')), 'UTF-8'));
        $add('xmailer:' . ($mailer !== '' ? mb_substr(preg_replace('/\d+/', '#', $mailer), 0, 40, 'UTF-8') : 'none'));
        $ctype = strtolower(trim(explode(';', (string)($f['content_type'] ?? ''))[0]));
        if ($ctype !== '') {
            $add('ctype:' . substr($ctype, 0, 40));
        }

        $text = substr((string)($f['text'] ?? ''), 0, self::MAX_BODY_BYTES);
        $html = substr((string)($f['html'] ?? ''), 0, self::MAX_BODY_BYTES);
        if (preg_match_all('#https?://([a-z0-9.\-]+)#i', $text . ' ' . $html, $mm)) {
            foreach ($mm[1] as $host) {
                $host = trim(strtolower($host), '.-');
                if ($host === '') {
                    continue;
                }
                $add('url:' . $host);
                $labels = explode('.', $host);
                if (count($labels) > 2) {
                    $add('url:' . implode('.', array_slice($labels, -2)));
                }
            }
        }

        if (trim($text) === '' && $html !== '') {
            $text = html_entity_decode(strip_tags((string)preg_replace('#<(script|style)\b.*?</\1>#is', ' ', $html)), ENT_QUOTES, 'UTF-8');
        }
        $text = (string)preg_replace('#(?:https?://|www\.)\S+#i', ' ', $text);
        foreach (self::words($text) as $w) {
            $add($w);
        }

        return array_keys($tokens);
    }

    /** Hex of the first 8 bytes of SHA-1 (the stored form of a token). */
    public static function hash(string $token): string
    {
        return substr(sha1($token), 0, 16);
    }

    /** @return string[] unique hex hashes */
    public static function hashes(array $tokens): array
    {
        return array_values(array_unique(array_map([self::class, 'hash'], $tokens)));
    }

    /** Signed 64-bit integer (BIGINT column) of a hex hash. */
    public static function hexToInt(string $hex): int
    {
        return unpack('J', hex2bin(str_pad($hex, 16, '0', STR_PAD_LEFT)))[1];
    }

    public static function intToHex(int|string $value): string
    {
        return bin2hex(pack('J', (int)$value));
    }

    /** Tokenizer input from a raw RFC 822 source (plugin reports, phishing, IMAP raw message). */
    public static function fieldsFromRaw(string $raw): array
    {
        $msg = new RawMessageParser($raw);
        $parts = $msg->getParts();

        return [
            'subject' => $msg->getSubject(),
            'from' => $msg->getFromAddress(),
            'reply_to' => $msg->getAddress('reply-to'),
            'message_id' => $msg->getHeader('message-id'),
            'x_mailer' => $msg->getHeader('x-mailer'),
            'content_type' => $msg->getHeader('content-type'),
            'text' => $parts['text'],
            'html' => $parts['html'],
        ];
    }

    /** Tokenizer input from an IMAP message (pipeline); every part is best effort. */
    public static function fieldsFromImap(MessageInterface $msg): array
    {
        $f = ['subject' => '', 'from' => '', 'reply_to' => '', 'message_id' => '', 'x_mailer' => '', 'content_type' => '', 'text' => '', 'html' => ''];
        try { $f['subject'] = (string)$msg->getSubject(); } catch (\Throwable $e) {}
        try { $f['from'] = $msg->getFrom() ? strtolower((string)$msg->getFrom()->getAddress()) : ''; } catch (\Throwable $e) {}
        try {
            $reply = $msg->getReplyTo();
            $f['reply_to'] = $reply ? strtolower((string)$reply[0]->getAddress()) : '';
        } catch (\Throwable $e) {}
        try { $f['message_id'] = (string)$msg->getId(); } catch (\Throwable $e) {}
        try {
            $raw = (string)$msg->getRawHeaders();
            $f['x_mailer'] = (string)(RawMessageParser::headerValues($raw, 'x-mailer')[0] ?? '');
            $f['content_type'] = (string)(RawMessageParser::headerValues($raw, 'content-type')[0] ?? '');
        } catch (\Throwable $e) {}
        try { $f['text'] = (string)$msg->getBodyText(); } catch (\Throwable $e) {}
        try { $f['html'] = (string)$msg->getBodyHtml(); } catch (\Throwable $e) {}

        return $f;
    }

    /** @return string[] */
    private static function words(string $text): array
    {
        $out = [];
        $text = mb_strtolower(self::utf8($text), 'UTF-8');
        foreach (preg_split('/[^\p{L}\p{N}\'$€\-]+/u', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $w) {
            $w = trim($w, "'-");
            $len = mb_strlen($w, 'UTF-8');
            if ($len < self::MIN_WORD || preg_match('/^[\d$€\'\-]+$/u', $w)) {
                continue;
            }
            if ($len > self::MAX_WORD) {
                $w = 'skip:' . mb_substr($w, 0, 1, 'UTF-8') . ':' . (intdiv($len, 10) * 10);
            }
            $out[] = $w;
        }
        return $out;
    }

    private static function domain(string $address): string
    {
        $p = strrpos($address, '@');
        return $p === false ? '' : strtolower(trim(substr($address, $p + 1), " \t<>."));
    }

    /** Valid UTF-8 (invalid bytes replaced), like mb_scrub() - which PHP 7.1 agents lack. */
    private static function utf8(string $s): string
    {
        return preg_match('//u', $s) ? $s : (string)mb_convert_encoding($s, 'UTF-8', 'UTF-8');
    }
}
