<?php

namespace AntispamBundle\Services;

/**
 * Undoes the spam marks a mail server / SpamAssassin left in a message when
 * it is released from SPAM (docs/users.md#releasing-mail-from-spam-myspam):
 *
 *   - a leading subject tag: "[SPAM] ", "***SPAM*** ", "*****SPAM***** ",
 *     "{Spam?} ", "[Possible Spam] ", "[Potencjalny SPAM] ", "SPAM: "…
 *     (repeated tags too, only in front of the subject);
 *   - "X-Spam-Flag: YES" -> "NO" and "X-Spam-Status: Yes," -> "No,", so a
 *     client that trusts SpamAssassin headers (Thunderbird) does not mark the
 *     released message as junk again.
 *
 * Only the header block changes; the body is never touched. The same logic
 * lives in the agent (agentCleanSpamTags(), AgentParityTest).
 */
final class SpamTagCleaner
{
    public const SUBJECT_TAG = '/^\s*(?:(?:\[|\{|\()\s*\**\s*(?:possible|suspected|potential|probable|likely|potencjalny|podejrzany|prawdopodobnie)?\s*(?:spam|junk)\s*\??\s*\**\s*(?:\]|\}|\))|\*+\s*(?:spam|junk)\s*\*+|(?:spam|junk)\s*:)\s*/i';

    /** "[SPAM] Faktura" -> "Faktura"; a subject without a tag is returned as is. */
    public static function cleanSubject(string $subject): string
    {
        $out = $subject;
        for ($i = 0; $i < 5; $i++) {
            $next = preg_replace(self::SUBJECT_TAG, '', $out, 1);
            if ($next === null || $next === $out) {
                break;
            }
            $out = $next;
        }
        // A subject that was only the tag stays as it was (nothing sensible to show otherwise).
        return trim($out) === '' ? $subject : $out;
    }

    /** The cleaned message, or null when there is nothing to change. */
    public static function clean(string $raw): ?string
    {
        if (!preg_match('/\r?\n\r?\n/', $raw, $m, PREG_OFFSET_CAPTURE)) {
            return null;
        }
        $split = $m[0][1];
        $headers = substr($raw, 0, $split);
        $rest = substr($raw, $split);

        $new = preg_replace_callback('/^(Subject:[ \t]*)([^\r\n]*)/mi', fn ($s) => $s[1] . self::cleanSubject($s[2]), $headers, 1);
        $new = preg_replace('/^(X-Spam-Flag:[ \t]*)yes\b/mi', '$1NO', (string)$new);
        $new = preg_replace('/^(X-Spam-Status:[ \t]*)yes\b/mi', '$1No', (string)$new);
        if ($new === null || $new === $headers) {
            return null;
        }
        return $new . $rest;
    }
}
