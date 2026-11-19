<?php

namespace AntispamBundle\Services;

/**
 * Field values of one message for ComplexRuleEngine::evaluate(). The header
 * block is parsed right away; the body (text + attachment names) only when a
 * rule asks for it - in IMAP mode that is a full download of the message.
 */
final class ComplexRuleMessage
{
    private RawMessageParser $head;
    /** @var \Closure|null returns the full raw source */
    private ?\Closure $rawLoader;
    private ?array $body = null;
    private array $cache = [];

    private string $headerBlock;

    /**
     * @param string|null $mailbox the mailbox being filtered (internal / external sender)
     * @param int|null    $size    message size in bytes when known without the body (IMAP RFC822.SIZE)
     */
    public function __construct(string $headerBlock, ?\Closure $rawLoader = null, private ?SenderIntelService $intel = null,
        private ?string $mailbox = null, private ?int $size = null)
    {
        $this->headerBlock = rtrim($headerBlock, "\r\n") . "\r\n";
        $this->head = new RawMessageParser($this->headerBlock . "\r\n");
        $this->rawLoader = $rawLoader;
    }

    public static function fromRaw(string $raw, ?SenderIntelService $intel = null, ?string $mailbox = null): self
    {
        $parts = preg_split('/\r?\n\r?\n/', $raw, 2);
        return new self((string)$parts[0], static fn () => $raw, $intel, $mailbox, strlen($raw));
    }

    /** Callable for ComplexRuleEngine::evaluate(). */
    public function provider(): callable
    {
        return fn (string $field, ?string $header = null) => $this->values($field, $header);
    }

    /** @return string[] */
    public function values(string $field, ?string $header = null): array
    {
        $key = $field . ':' . strtolower((string)$header);
        if (!array_key_exists($key, $this->cache)) {
            $this->cache[$key] = array_values(array_filter($this->compute($field, $header), fn ($v) => $v !== ''));
        }
        return $this->cache[$key];
    }

    private function compute(string $field, ?string $header): array
    {
        $h = $this->head;
        switch ($field) {
            case 'from': return [$h->getFromAddress()];
            case 'from_domain': return [$h->getFromHost()];
            case 'from_name': return [$h->getFromName()];
            case 'subject': return [$h->getSubject()];
            case 'to': return self::addresses(array_merge($h->getDecodedHeaders('to'), $h->getDecodedHeaders('cc')));
            case 'reply_to': return self::addresses($h->getDecodedHeaders('reply-to'));
            case 'return_path': return self::addresses($h->getDecodedHeaders('return-path'));
            case 'from_scope': return $h->getFromHost() === '' ? [] : [self::scopeOf($h->getFromHost(), $this->mailbox)];
            case 'from_freemail': return $h->getFromHost() === '' ? [] : [DomainHelper::isFreemail($h->getFromHost()) ? 'tak' : 'nie'];
            case 'message_type': return self::messageTypes($h);
            case 'sender_ip': return ($ip = $h->getConnectingIp()) ? [$ip] : [];
            case 'size_kb':
                $size = $this->size ?? ($this->rawLoader ? strlen((string)($this->rawLoader)()) : null);
                return $size === null ? [] : [(string)intdiv($size + 1023, 1024)];
            case 'attachment_type': return $this->body()['types'];
            case 'attachment_count': return [(string)count($this->body()['types'])];
            case 'header': return $header === null ? [] : $h->getDecodedHeaders($header);
            case 'body': return [$this->body()['text']];
            case 'attachment': return $this->body()['attachments'];
            case 'link_domain': return $this->body()['links'];
            case 'auth_spf':
            case 'auth_dkim':
            case 'auth_dmarc':
                return self::authResults($this->headerBlock, substr($field, 5));
            case 'mx_provider': return $this->intel ? [$this->intel->mxProvider($h->getFromHost())] : [];
            case 'mx_host': return $this->intel ? $this->intel->mxHosts($h->getFromHost()) : [];
            case 'domain_age':
                $days = $this->intel ? $this->intel->domainAgeDays($h->getFromHost()) : null;
                return $days === null ? [] : [(string)$days];
        }
        return [];
    }

    /**
     * Results of one method (spf | dkim | dmarc) in the topmost
     * Authentication-Results - the receiving server's, like HeaderAnalyzer;
     * SPF falls back to the topmost Received-SPF.
     *
     * @return string[] e.g. ['pass'] or ['fail', 'pass'] for two DKIM signatures
     */
    public static function authResults(string $headerBlock, string $method): array
    {
        $auth = strtolower(HeaderAnalyzer::topmostAuthResults($headerBlock));
        $out = [];
        if (preg_match_all('/\b' . preg_quote($method, '/') . '\s*=\s*([a-z]+)/', $auth, $m)) {
            $out = $m[1];
        }
        if (!$out && $method === 'spf') {
            $rspf = strtolower(ltrim((string)(RawMessageParser::headerValues($headerBlock, 'received-spf')[0] ?? '')));
            if (preg_match('/^([a-z]+)/', $rspf, $m)) {
                $out = [$m[1]];
            }
        }
        return array_values(array_unique($out));
    }

    /** "internal" when the sender's registered domain is the mailbox's, else (also: mailbox unknown) "external". */
    public static function scopeOf(string $fromHost, ?string $mailbox): string
    {
        $mine = $mailbox !== null && str_contains($mailbox, '@') ? substr($mailbox, strrpos($mailbox, '@') + 1) : '';
        return $mine !== '' && DomainHelper::registrable($mine) === DomainHelper::registrable($fromHost) ? 'internal' : 'external';
    }

    /**
     * autoreply, bounce, list, calendar, signed, encrypted, readreceipt -
     * from the top-level headers only (an invitation nested in
     * multipart/alternative: use attachment_type = text/calendar).
     */
    public static function messageTypes(RawMessageParser $h): array
    {
        $out = [];
        $auto = strtolower(trim($h->getHeader('auto-submitted')));
        if (($auto !== '' && $auto !== 'no') || $h->getHeader('x-autoreply') !== '' || $h->getHeader('x-autorespond') !== ''
            || in_array(strtolower(trim($h->getHeader('precedence'))), ['auto_reply'], true)) {
            $out[] = 'autoreply';
        }
        $ct = strtolower($h->getHeader('content-type'));
        if (str_starts_with($ct, 'multipart/report') && str_contains($ct, 'delivery-status')) {
            $out[] = 'bounce';
        }
        if (str_starts_with($ct, 'multipart/report') && str_contains($ct, 'disposition-notification')) {
            $out[] = 'readreceipt';
        }
        if ($h->getHeader('list-id') !== '' || $h->getHeader('list-unsubscribe') !== '' || in_array(strtolower(trim($h->getHeader('precedence'))), ['bulk', 'list'], true)) {
            $out[] = 'list';
        }
        if (str_contains($ct, 'text/calendar') || str_contains($ct, 'method=request')) {
            $out[] = 'calendar';
        }
        if (str_starts_with($ct, 'multipart/signed')) {
            $out[] = 'signed';
        }
        if (str_starts_with($ct, 'multipart/encrypted') || str_contains($ct, 'application/pkcs7-mime')) {
            $out[] = 'encrypted';
        }
        return $out;
    }

    /** @return array{text:string, attachments:string[], links:string[], types:string[]} */
    private function body(): array
    {
        if ($this->body === null) {
            $this->body = ['text' => '', 'attachments' => [], 'links' => [], 'types' => []];
            try {
                $raw = $this->rawLoader ? (string)($this->rawLoader)() : '';
                if ($raw !== '') {
                    $p = new RawMessageParser($raw);
                    $parts = $p->getParts();
                    $text = $parts['text'] !== '' ? $parts['text']
                        : html_entity_decode(strip_tags(preg_replace('#<(script|style)\b.*?</\1>#is', '', $parts['html']) ?? ''), ENT_QUOTES, 'UTF-8');
                    $this->body['text'] = mb_substr(mb_scrub($text, 'UTF-8'), 0, ComplexRuleEngine::MAX_BODY, 'UTF-8');
                    $this->body['links'] = array_values(array_unique(CertHoleService::linkHosts($parts['html'], $parts['text'])));
                    foreach ($parts['attachments'] as $a) {
                        $this->body['types'][] = strtolower((string)($a['type'] ?? 'application/octet-stream'));
                        if (($a['filename'] ?? '') !== '') {
                            $this->body['attachments'][] = mb_scrub((string)$a['filename'], 'UTF-8');
                        }
                    }
                }
            } catch (\Throwable $e) {
                // Unreadable body: body / attachment conditions see nothing.
            }
        }
        return $this->body;
    }

    /** Lower-cased addresses found in address header values. */
    public static function addresses(array $values): array
    {
        $out = [];
        foreach ($values as $v) {
            if (preg_match_all('/[^\s<>"\',;:()]+@[^\s<>"\',;:()]+/', (string)$v, $m)) {
                foreach ($m[0] as $a) {
                    $out[] = strtolower(rtrim($a, '.'));
                }
            }
        }
        return array_values(array_unique($out));
    }
}
