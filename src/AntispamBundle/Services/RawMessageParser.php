<?php

namespace AntispamBundle\Services;

/**
 * Minimal RFC 822 / MIME parser for raw messages submitted over HTTP (the
 * Thunderbird plugin sends the full source of a message). It only extracts
 * what the scoring pipeline needs: the header block, a few decoded headers,
 * the sender address, the connecting IP and a plain-text body.
 *
 * Everything is defensive: malformed input yields empty values, never an
 * exception.
 */
class RawMessageParser
{
    /** Guard against pathological nesting in hostile MIME trees. */
    const MAX_DEPTH = 8;
    /** ...and against a flat tree of thousands of tiny parts / header lines. */
    const MAX_PARTS = 500;
    const MAX_HEADER_LINES = 2000;

    private $headerBlock = '';
    private $partsSeen = 0;
    private $body = '';
    private $headers = [];

    public function __construct($raw)
    {
        list($this->headerBlock, $this->body) = self::split((string)$raw);
        $this->headers = self::parseHeaders($this->headerBlock);
    }

    /** Raw (still folded) header block, as expected by HeaderAnalyzer::analyzeRaw(). */
    public function getHeaderBlock()
    {
        return $this->headerBlock;
    }

    /**
     * First value of a header, unfolded and MIME-decoded ('' when absent).
     * Always valid UTF-8 (raw 8-bit bytes become '?'), so it can be stored in
     * utf8mb4 columns and escaped by Twig.
     */
    public function getHeader($name)
    {
        $values = $this->headers[strtolower($name)] ?? [];
        return $values ? mb_scrub(self::decodeWords($values[0]), 'UTF-8') : '';
    }

    /**
     * Every header in original order, unfolded and MIME-decoded, for display.
     *
     * @return array<int, array{name:string, value:string}>
     */
    public function getHeaderList()
    {
        $out = [];
        $unfolded = preg_replace('/\r?\n[ \t]+/', ' ', $this->headerBlock);
        foreach (preg_split('/\r?\n/', $unfolded, self::MAX_HEADER_LINES + 1) as $i => $line) {
            $colon = strpos($line, ':');
            if ($i >= self::MAX_HEADER_LINES || $colon === false || $colon === 0) {
                continue;
            }
            $out[] = ['name' => mb_scrub(trim(substr($line, 0, $colon)), 'UTF-8'), 'value' => mb_scrub(self::decodeWords(trim(substr($line, $colon + 1))), 'UTF-8')];
        }
        return $out;
    }

    /** Address of an address header such as Reply-To or Return-Path ('' when missing). */
    public function getAddress($header)
    {
        return self::extractEmail($this->getHeader($header));
    }

    /** @return string[] all values of a header (e.g. every Received line) */
    public function getHeaders($name)
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    public function getSubject()
    {
        return $this->getHeader('subject');
    }

    /** Lower-cased From address ('' when missing). */
    public function getFromAddress()
    {
        return self::extractEmail($this->getHeader('from'));
    }

    /** Display name of the From header, MIME-decoded ('' when missing). */
    public function getFromName()
    {
        $from = $this->getHeader('from');
        $p = strpos($from, '<');
        return $p === false ? '' : trim(substr($from, 0, $p), " \t\"'");
    }

    /** Domain part of the From address ('' when missing). */
    public function getFromHost()
    {
        $parts = explode('@', $this->getFromAddress(), 2);
        return $parts[1] ?? '';
    }

    /**
     * IP of the connecting host taken from the topmost Received header that
     * carries a public address, mirroring CheckDnsbl for IMAP messages.
     */
    public function getConnectingIp()
    {
        foreach ($this->getHeaders('received') as $line) {
            if (preg_match_all('/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/', $line, $m)) {
                foreach ($m[1] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Plain-text body: the first text/plain part, falling back to a stripped
     * text/html part. Transfer encoding and charset are decoded to UTF-8.
     */
    public function getBodyText()
    {
        $plain = null;
        $html = null;
        $this->partsSeen = 0;
        $this->walk($this->headers, $this->body, 0, $plain, $html);
        if ($plain !== null && trim($plain) !== '') {
            return $plain;
        }
        if ($html !== null) {
            return html_entity_decode(strip_tags(preg_replace('#<(script|style)\b.*?</\1>#is', '', $html)), ENT_QUOTES, 'UTF-8');
        }
        return '';
    }

    /**
     * First text/plain and text/html bodies plus every attachment, for the
     * link and attachment-policy analyzers.
     *
     * @return array{text:string, html:string, attachments:array<int, array{filename:string, type:string, data:string}>}
     */
    public function getParts()
    {
        $out = ['text' => '', 'html' => '', 'attachments' => []];
        $this->partsSeen = 0;
        $this->collect($this->headers, $this->body, 0, $out);
        return $out;
    }

    private function collect(array $headers, $body, $depth, array &$out)
    {
        if ($depth > self::MAX_DEPTH || ++$this->partsSeen > self::MAX_PARTS) {
            return;
        }
        $contentType = $headers['content-type'][0] ?? 'text/plain';
        $type = strtolower(trim(explode(';', $contentType)[0]));

        if (strpos($type, 'multipart/') === 0) {
            $boundary = self::param($contentType, 'boundary');
            if ($boundary === '') {
                return;
            }
            $parts = preg_split('/\r?\n--' . preg_quote($boundary, '/') . '(?:--)?[ \t]*(?:\r?\n|$)/', "\n" . $body);
            array_shift($parts); // preamble
            foreach ($parts as $part) {
                list($ph, $pb) = self::split($part);
                $this->collect(self::parseHeaders($ph), $pb, $depth + 1, $out);
            }
            return;
        }

        $disposition = $headers['content-disposition'][0] ?? '';
        $filename = self::param($disposition, 'filename') ?: self::param($disposition, 'filename*') ?: self::param($contentType, 'name');
        $decoded = self::decodeTransfer($body, $headers['content-transfer-encoding'][0] ?? '');

        $isText = $type === 'text/plain' || $type === 'text/html';
        if (stripos($disposition, 'attachment') === 0 || $filename !== '' || !$isText) {
            if ($decoded !== '' && strpos($type, 'multipart/') !== 0) {
                $out['attachments'][] = ['filename' => self::decodeWords($filename), 'type' => $type, 'data' => $decoded];
            }
            return;
        }
        $key = $type === 'text/html' ? 'html' : 'text';
        if ($out[$key] === '') {
            $out[$key] = self::toUtf8($decoded, self::param($contentType, 'charset'));
        }
    }

    private function walk(array $headers, $body, $depth, &$plain, &$html)
    {
        if ($depth > self::MAX_DEPTH || ($plain !== null && $html !== null) || ++$this->partsSeen > self::MAX_PARTS) {
            return;
        }
        $contentType = $headers['content-type'][0] ?? 'text/plain';
        $type = strtolower(trim(explode(';', $contentType)[0]));

        if (strpos($type, 'multipart/') === 0) {
            $boundary = self::param($contentType, 'boundary');
            if ($boundary === '') {
                return;
            }
            $parts = preg_split('/\r?\n--' . preg_quote($boundary, '/') . '(?:--)?[ \t]*(?:\r?\n|$)/', "\n" . $body);
            array_shift($parts); // preamble
            foreach ($parts as $part) {
                list($ph, $pb) = self::split($part);
                $this->walk(self::parseHeaders($ph), $pb, $depth + 1, $plain, $html);
            }
            return;
        }

        $disposition = strtolower($headers['content-disposition'][0] ?? '');
        if (strpos($disposition, 'attachment') === 0) {
            return;
        }
        if ($type !== 'text/plain' && $type !== 'text/html') {
            return;
        }

        $decoded = self::decodeTransfer($body, $headers['content-transfer-encoding'][0] ?? '');
        $decoded = self::toUtf8($decoded, self::param($contentType, 'charset'));

        if ($type === 'text/plain' && $plain === null) {
            $plain = $decoded;
        } elseif ($type === 'text/html' && $html === null) {
            $html = $decoded;
        }
    }

    /** @return array{0:string,1:string} [header block, body] */
    private static function split($raw)
    {
        $pos = strpos($raw, "\r\n\r\n");
        $sep = 4;
        $lf = strpos($raw, "\n\n");
        if ($pos === false || ($lf !== false && $lf < $pos)) {
            $pos = $lf;
            $sep = 2;
        }
        if ($pos === false) {
            return [$raw, ''];
        }
        return [substr($raw, 0, $pos), substr($raw, $pos + $sep)];
    }

    /** @return array<string, string[]> lower-cased name => unfolded values */
    private static function parseHeaders($block)
    {
        $headers = [];
        $unfolded = preg_replace('/\r?\n[ \t]+/', ' ', (string)$block);
        foreach (preg_split('/\r?\n/', $unfolded) as $line) {
            $colon = strpos($line, ':');
            if ($colon === false || $colon === 0) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            $headers[$name][] = trim(substr($line, $colon + 1));
        }
        return $headers;
    }

    private static function param($headerValue, $name)
    {
        if (preg_match('/;\s*' . preg_quote($name, '/') . '\s*=\s*(?:"([^"]*)"|([^;\s]+))/i', (string)$headerValue, $m)) {
            return $m[1] !== '' ? $m[1] : ($m[2] ?? '');
        }
        return '';
    }

    private static function decodeTransfer($body, $encoding)
    {
        switch (strtolower(trim($encoding))) {
            case 'base64':
                $out = base64_decode(preg_replace('/[^A-Za-z0-9+\/=]/', '', $body), false);
                return $out === false ? '' : $out;
            case 'quoted-printable':
                return quoted_printable_decode($body);
            default:
                return $body;
        }
    }

    private static function toUtf8($text, $charset)
    {
        $charset = strtoupper(trim((string)$charset));
        if ($charset === '' || $charset === 'UTF-8' || $charset === 'US-ASCII') {
            return $text;
        }
        $out = @iconv($charset, 'UTF-8//IGNORE', $text);
        return $out === false ? $text : $out;
    }

    private static function decodeWords($value)
    {
        if (strpos($value, '=?') === false) {
            return $value;
        }
        $out = @iconv_mime_decode($value, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
        return $out === false ? $value : $out;
    }

    private static function extractEmail($line)
    {
        if (preg_match('/<([^<>\s]+@[^<>\s]+)>/', (string)$line, $m)) {
            return strtolower($m[1]);
        }
        if (preg_match('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', (string)$line, $m)) {
            return strtolower($m[0]);
        }
        return '';
    }
}
