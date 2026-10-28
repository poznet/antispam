<?php

namespace AntispamBundle\Imap;

/**
 * Minimal IMAP4rev1 client over a PHP socket stream, for the accounts that
 * log in with OAuth2 (SASL XOAUTH2): ext-imap (c-client) cannot do XOAUTH2.
 *
 * Only what the pipeline needs: CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE
 * XOAUTH2, LIST, CREATE, DELETE, RENAME, STATUS, SELECT, UID SEARCH,
 * UID FETCH, UID STORE, UID COPY, UID MOVE (RFC 6851), EXPUNGE / UID EXPUNGE
 * (RFC 4315), APPEND, NOOP, LOGOUT. Every message is addressed by UID.
 *
 * Responses are read as "logical lines": a line ending with a literal
 * marker {n} is followed by exactly n bytes and the rest of the line.
 * Nothing written to the server (tokens, passwords) is ever logged or put
 * into an exception message.
 */
final class ImapClient
{
    public const ENC_SSL = 'ssl';
    public const ENC_STARTTLS = 'tls';
    public const ENC_NONE = 'none';

    /** Largest literal accepted from the server (a message body is capped lower by the caller). */
    public const MAX_LITERAL = 64 * 1024 * 1024;
    /** Largest logical response line (e.g. UID SEARCH of a huge mailbox). */
    public const MAX_LINE = 16 * 1024 * 1024;

    /** @var resource|null */
    private $stream;
    private int $tag = 0;
    /** @var array<string, true> upper-cased capabilities */
    private array $capabilities = [];
    private ?string $selected = null;

    public function __construct(private int $timeout = 120, private int $connectTimeout = 15)
    {
    }

    /** Wraps an already connected stream (tests: one end of stream_socket_pair()). */
    public static function fromStream($stream, int $timeout = 10): self
    {
        $client = new self($timeout);
        $client->stream = $stream;
        stream_set_timeout($stream, $timeout);
        $client->readGreeting();
        return $client;
    }

    public function connect(string $host, int $port, string $encryption = self::ENC_SSL, bool $validateCert = true): void
    {
        $host = trim($host);
        $bare = trim($host, '[]');
        $context = stream_context_create(['ssl' => [
            'verify_peer' => $validateCert,
            'verify_peer_name' => $validateCert,
            'allow_self_signed' => !$validateCert,
            'peer_name' => $bare,
            'SNI_enabled' => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT,
        ]]);
        $address = filter_var($bare, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? '[' . $bare . ']' : $bare;
        $remote = ($encryption === self::ENC_SSL ? 'ssl' : 'tcp') . '://' . $address . ':' . $port;

        $errno = 0;
        $error = '';
        $stream = @stream_socket_client($remote, $errno, $error, $this->connectTimeout, STREAM_CLIENT_CONNECT, $context);
        if (!$stream) {
            throw new ImapException(sprintf('Nie można połączyć się z serwerem IMAP %s:%d (%s)', $bare, $port, $error !== '' ? $error : 'błąd ' . $errno));
        }
        stream_set_timeout($stream, $this->timeout);
        $this->stream = $stream;
        $this->readGreeting();

        if ($encryption === self::ENC_STARTTLS) {
            $this->ok('STARTTLS');
            if (!@stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                $this->disconnect();
                throw new ImapException('STARTTLS: nie udało się nawiązać szyfrowanego połączenia z ' . $bare);
            }
            $this->capabilities = []; // must not be trusted from before TLS (RFC 3501 6.2.1)
        }
        if (!$this->capabilities) {
            $this->refreshCapabilities();
        }
    }

    public function isConnected(): bool
    {
        return is_resource($this->stream);
    }

    /** @return string[] */
    public function capabilities(): array
    {
        return array_keys($this->capabilities);
    }

    public function hasCapability(string $name): bool
    {
        return isset($this->capabilities[strtoupper($name)]);
    }

    public function refreshCapabilities(): void
    {
        $response = $this->ok('CAPABILITY');
        $this->capabilities = [];
        foreach ($response->untagged as $line) {
            if (strncasecmp($line, 'CAPABILITY ', 11) === 0) {
                $this->setCapabilities(substr($line, 11));
            }
        }
    }

    /**
     * SASL XOAUTH2 initial client response (Google / Microsoft):
     * base64("user=" user ^A "auth=Bearer " token ^A ^A).
     */
    public static function xoauth2(string $user, string $accessToken): string
    {
        if (preg_match('/[\x00-\x1f\x7f]/', $user . $accessToken)) {
            throw new \InvalidArgumentException('XOAUTH2: control characters in user or token');
        }
        return base64_encode('user=' . $user . "\x01auth=Bearer " . $accessToken . "\x01\x01");
    }

    public function authenticateXoauth2(string $user, string $accessToken): void
    {
        if ($this->capabilities && !$this->hasCapability('AUTH=XOAUTH2')) {
            throw new ImapException('Serwer IMAP nie obsługuje logowania OAuth2 (brak AUTH=XOAUTH2)');
        }
        $initial = self::xoauth2($user, $accessToken);
        $response = $this->hasCapability('SASL-IR')
            ? $this->command('AUTHENTICATE XOAUTH2 ' . $initial)
            : $this->command('AUTHENTICATE XOAUTH2', $initial);
        if (!$response->isOk()) {
            $detail = '';
            foreach ($response->challenges as $challenge) {
                $json = json_decode((string)base64_decode(trim($challenge), true), true);
                if (is_array($json)) {
                    $detail = ' (' . implode(', ', array_map(static fn ($k, $v) => $k . '=' . (is_scalar($v) ? $v : json_encode($v)), array_keys($json), $json)) . ')';
                }
            }
            throw new ImapException('Logowanie OAuth2 (XOAUTH2) odrzucone przez serwer IMAP: ' . self::clip($response->text) . $detail);
        }
        $this->afterLogin($response);
    }

    public function login(string $user, string $password): void
    {
        if ($this->hasCapability('LOGINDISABLED')) {
            throw new ImapException('Serwer IMAP nie pozwala na LOGIN bez szyfrowania (LOGINDISABLED)');
        }
        $response = $this->command('LOGIN ' . self::quote($user) . ' ' . self::quote($password));
        if (!$response->isOk()) {
            throw new ImapException('Logowanie IMAP odrzucone: ' . self::clip($response->text));
        }
        $this->afterLogin($response);
    }

    /**
     * @return array<int, array{name: string, delimiter: string, attributes: string[]}>
     */
    public function listMailboxes(string $pattern = '*'): array
    {
        $response = $this->ok('LIST "" ' . self::quoteMailbox($pattern));
        $out = [];
        foreach ($response->untagged as $line) {
            if (strncasecmp($line, 'LIST ', 5) !== 0) {
                continue;
            }
            $tokens = self::tokenize(substr($line, 5));
            if (count($tokens) < 3 || !is_array($tokens[0])) {
                continue;
            }
            $out[] = [
                'name' => self::decodeMailbox((string)$tokens[2]),
                'delimiter' => (string)($tokens[1] ?? ''),
                'attributes' => array_map('strval', $tokens[0]),
            ];
        }
        return $out;
    }

    public function createMailbox(string $name): void
    {
        $this->ok('CREATE ' . self::quoteMailbox($name));
    }

    public function deleteMailbox(string $name): void
    {
        if ($this->selected !== null && strcasecmp($this->selected, $name) === 0) {
            $this->selected = null;
        }
        $this->ok('DELETE ' . self::quoteMailbox($name));
    }

    public function renameMailbox(string $from, string $to): void
    {
        $this->ok('RENAME ' . self::quoteMailbox($from) . ' ' . self::quoteMailbox($to));
        if ($this->selected === $from) {
            $this->selected = null;
        }
    }

    /** @return array<string, int> lower-cased STATUS items (messages, recent, unseen, uidnext, uidvalidity) */
    public function status(string $mailbox, array $items = ['MESSAGES', 'RECENT', 'UNSEEN', 'UIDNEXT', 'UIDVALIDITY']): array
    {
        $response = $this->ok('STATUS ' . self::quoteMailbox($mailbox) . ' (' . implode(' ', $items) . ')');
        $out = [];
        foreach ($response->untagged as $line) {
            if (strncasecmp($line, 'STATUS ', 7) !== 0) {
                continue;
            }
            $tokens = self::tokenize(substr($line, 7));
            $list = $tokens[1] ?? null;
            if (!is_array($list)) {
                continue;
            }
            for ($i = 0; $i + 1 < count($list); $i += 2) {
                $out[strtolower((string)$list[$i])] = (int)$list[$i + 1];
            }
        }
        return $out;
    }

    /** SELECT (read-write) unless that mailbox is already selected. */
    public function select(string $mailbox): void
    {
        if ($this->selected === $mailbox) {
            return;
        }
        $this->selected = null;
        $this->ok('SELECT ' . self::quoteMailbox($mailbox));
        $this->selected = $mailbox;
    }

    public function getSelected(): ?string
    {
        return $this->selected;
    }

    /**
     * UID SEARCH in the selected mailbox. Criteria must be plain ASCII
     * (ddeboer search conditions: ALL, SINCE "d-M-Y", FROM "x", UID n:*).
     *
     * @return int[] ascending UIDs
     */
    public function uidSearch(string $criteria = 'ALL'): array
    {
        $criteria = trim($criteria) === '' ? 'ALL' : trim($criteria);
        if (!preg_match('/^[\x20-\x7e]+$/', $criteria)) {
            throw new ImapException('Nieprawidłowe kryteria wyszukiwania IMAP (tylko ASCII)');
        }
        $response = $this->ok('UID SEARCH ' . $criteria);
        $uids = [];
        foreach ($response->untagged as $line) {
            if (strncasecmp($line, 'SEARCH', 6) !== 0) {
                continue;
            }
            foreach (preg_split('/\s+/', trim(substr($line, 6))) as $n) {
                // "(MODSEQ n)" of CONDSTORE servers and empty strings are skipped.
                if (ctype_digit($n)) {
                    $uids[(int)$n] = (int)$n;
                }
            }
        }
        ksort($uids, SORT_NUMERIC);
        return array_values($uids);
    }

    /**
     * UID FETCH; returns the data items per UID with upper-cased names
     * (FLAGS, INTERNALDATE, RFC822.SIZE, BODY[HEADER], BODY[] ...). A partial
     * fetch "BODY[]<0>" is returned as "BODY[]".
     *
     * @param int[]|string $uids
     * @return array<int, array<string, mixed>>
     */
    public function uidFetch($uids, string $items): array
    {
        $set = self::uidSet($uids);
        $response = $this->ok('UID FETCH ' . $set . ' (' . $items . ')');
        $out = [];
        foreach ($response->untagged as $line) {
            if (!preg_match('/^\d+ FETCH /i', $line, $m)) {
                continue;
            }
            $tokens = self::tokenize(substr($line, strlen($m[0])));
            $list = $tokens[0] ?? null;
            if (!is_array($list)) {
                continue;
            }
            $data = [];
            for ($i = 0; $i + 1 < count($list); $i += 2) {
                $key = strtoupper((string)$list[$i]);
                $key = preg_replace('/<\d+>$/', '', $key);
                $data[$key] = $list[$i + 1];
            }
            // Unsolicited FETCH (flag changes by another client) has no UID.
            if (!isset($data['UID']) || !ctype_digit((string)$data['UID'])) {
                continue;
            }
            $uid = (int)$data['UID'];
            $out[$uid] = isset($out[$uid]) ? $data + $out[$uid] : $data;
        }
        return $out;
    }

    /** @param int[]|string $uids */
    public function uidStore($uids, string $mode, array $flags): void
    {
        if (!in_array($mode, ['+FLAGS', '-FLAGS', 'FLAGS', '+FLAGS.SILENT', '-FLAGS.SILENT', 'FLAGS.SILENT'], true)) {
            throw new \InvalidArgumentException('Invalid STORE mode');
        }
        foreach ($flags as $flag) {
            if (!preg_match('/^\\\\?[A-Za-z0-9$_.\-]+$/', $flag)) {
                throw new \InvalidArgumentException('Invalid flag ' . $flag);
            }
        }
        $this->ok('UID STORE ' . self::uidSet($uids) . ' ' . $mode . ' (' . implode(' ', $flags) . ')');
    }

    /** @param int[]|string $uids */
    public function uidCopy($uids, string $mailbox): void
    {
        $this->ok('UID COPY ' . self::uidSet($uids) . ' ' . self::quoteMailbox($mailbox));
    }

    /** @param int[]|string $uids */
    public function uidMove($uids, string $mailbox): void
    {
        $this->ok('UID MOVE ' . self::uidSet($uids) . ' ' . self::quoteMailbox($mailbox));
    }

    /**
     * Removes \Deleted messages of the selected mailbox; with UIDPLUS and
     * UIDs given only those (messages another client flagged stay).
     *
     * @param int[] $uids
     */
    public function expunge(array $uids = []): void
    {
        if ($uids && $this->hasCapability('UIDPLUS')) {
            $this->ok('UID EXPUNGE ' . self::uidSet($uids));
            return;
        }
        $this->ok('EXPUNGE');
    }

    public function append(string $mailbox, string $message, array $flags = [], ?\DateTimeInterface $internalDate = null): void
    {
        foreach ($flags as $flag) {
            if (!preg_match('/^\\\\?[A-Za-z0-9$_.\-]+$/', $flag)) {
                throw new \InvalidArgumentException('Invalid flag ' . $flag);
            }
        }
        $command = 'APPEND ' . self::quoteMailbox($mailbox)
            . ($flags ? ' (' . implode(' ', $flags) . ')' : '')
            . ($internalDate ? ' "' . $internalDate->format('d-M-Y H:i:s O') . '"' : '')
            . ' {' . strlen($message) . '}';
        $response = $this->command($command, $message);
        if (!$response->isOk()) {
            throw new ImapException('APPEND: ' . self::clip($response->text));
        }
    }

    public function noop(): bool
    {
        try {
            return $this->command('NOOP')->isOk();
        } catch (ImapException) {
            return false;
        }
    }

    /** LOGOUT and close; never throws. */
    public function logout(): void
    {
        if (!is_resource($this->stream)) {
            return;
        }
        try {
            $this->command('LOGOUT');
        } catch (\Throwable) {
            // closing anyway
        }
        $this->disconnect();
    }

    public function disconnect(): void
    {
        if (is_resource($this->stream)) {
            @fclose($this->stream);
        }
        $this->stream = null;
        $this->selected = null;
    }

    /** Runs a command and throws unless the answer is OK. */
    public function ok(string $command, ?string $continuation = null): ImapResponse
    {
        $response = $this->command($command, $continuation);
        if (!$response->isOk()) {
            $verb = strtoupper(strtok($command, ' '));
            if ($verb === 'UID') {
                $verb .= ' ' . strtoupper((string)strtok(' '));
            }
            throw new ImapException(sprintf('IMAP %s: %s %s', $verb, $response->status, self::clip($response->text)));
        }
        return $response;
    }

    /**
     * Sends one tagged command and collects the answer. $continuation is sent
     * (followed by CRLF) on the first "+" from the server - SASL initial
     * response or an APPEND literal. Any later "+" (e.g. a XOAUTH2 error
     * challenge) is recorded and answered with an empty line, as SASL requires.
     */
    public function command(string $command, ?string $continuation = null): ImapResponse
    {
        if (!is_resource($this->stream)) {
            throw new ImapException('Brak połączenia z serwerem IMAP');
        }
        if (preg_match('/[\r\n\x00]/', $command)) {
            throw new \InvalidArgumentException('IMAP command must be a single line');
        }
        $tag = 'A' . str_pad((string)++$this->tag, 4, '0', STR_PAD_LEFT);
        $this->write($tag . ' ' . $command . "\r\n");

        $untagged = [];
        $challenges = [];
        while (true) {
            $line = $this->readResponse();
            if ($line === '+' || strncmp($line, '+ ', 2) === 0) {
                if ($continuation !== null) {
                    $this->write($continuation . "\r\n");
                    $continuation = null;
                } else {
                    $challenges[] = (string)substr($line, 2);
                    $this->write("\r\n");
                }
                continue;
            }
            if (strncmp($line, '* ', 2) === 0) {
                $untagged[] = substr($line, 2);
                if (strncasecmp($line, '* BYE', 5) === 0 && strncasecmp($command, 'LOGOUT', 6) !== 0) {
                    // The server will close the connection; the tagged answer may never come.
                    $this->disconnect();
                    throw new ImapException('Serwer IMAP zakończył połączenie: ' . self::clip(substr($line, 6)));
                }
                if (preg_match('/^\* OK \[CAPABILITY ([^\]]*)\]/i', $line, $m)) {
                    $this->setCapabilities($m[1]);
                }
                continue;
            }
            if (strncmp($line, $tag . ' ', strlen($tag) + 1) === 0) {
                $rest = substr($line, strlen($tag) + 1);
                $space = strpos($rest, ' ');
                $status = strtoupper($space === false ? $rest : substr($rest, 0, $space));
                $text = $space === false ? '' : substr($rest, $space + 1);
                if ($status === 'OK' && preg_match('/^\[CAPABILITY ([^\]]*)\]/i', $text, $m)) {
                    $this->setCapabilities($m[1]);
                }
                return new ImapResponse($status, $text, $untagged, $challenges);
            }
            // Answer to another tag: not ours, ignore.
        }
    }

    // ---- response parsing ---------------------------------------------------

    /**
     * Parses IMAP data (atoms, "quoted", {n} literals, NIL, nested lists).
     * Atoms keep [...] sections whole, so "BODY[HEADER.FIELDS (FROM)]" and
     * "BODY[]<0>" are one token.
     *
     * @return array<int, string|array|null>
     */
    public static function tokenize(string $data): array
    {
        $pos = 0;
        return self::parseTokens($data, $pos, false);
    }

    private static function parseTokens(string $s, int &$pos, bool $inList): array
    {
        $out = [];
        $len = strlen($s);
        while ($pos < $len) {
            $c = $s[$pos];
            if ($c === ' ' || $c === "\r" || $c === "\n") {
                $pos++;
                continue;
            }
            if ($c === '(') {
                $pos++;
                $out[] = self::parseTokens($s, $pos, true);
                continue;
            }
            if ($c === ')') {
                $pos++;
                if ($inList) {
                    return $out;
                }
                continue;
            }
            if ($c === '"') {
                $pos++;
                $value = '';
                while ($pos < $len) {
                    $ch = $s[$pos];
                    if ($ch === '\\' && $pos + 1 < $len) {
                        $value .= $s[$pos + 1];
                        $pos += 2;
                        continue;
                    }
                    $pos++;
                    if ($ch === '"') {
                        break;
                    }
                    $value .= $ch;
                }
                $out[] = $value;
                continue;
            }
            if ($c === '{' && preg_match('/\G\{(\d+)\+?\}\r\n/', $s, $m, 0, $pos)) {
                $pos += strlen($m[0]);
                $out[] = (string)substr($s, $pos, (int)$m[1]);
                $pos += (int)$m[1];
                continue;
            }
            $start = $pos;
            $depth = 0;
            while ($pos < $len) {
                $ch = $s[$pos];
                if ($ch === '[') {
                    $depth++;
                } elseif ($ch === ']') {
                    $depth--;
                } elseif ($depth <= 0 && ($ch === ' ' || $ch === '(' || $ch === ')' || $ch === "\r" || $ch === "\n")) {
                    break;
                }
                $pos++;
            }
            $atom = substr($s, $start, $pos - $start);
            $out[] = strtoupper($atom) === 'NIL' ? null : $atom;
        }
        return $out;
    }

    private function readGreeting(): void
    {
        $greeting = $this->readResponse();
        if (!preg_match('/^\* (OK|PREAUTH)\b/i', $greeting)) {
            $this->disconnect();
            throw new ImapException('Nieoczekiwane powitanie serwera IMAP: ' . self::clip($greeting));
        }
        if (preg_match('/\[CAPABILITY ([^\]]*)\]/i', $greeting, $m)) {
            $this->setCapabilities($m[1]);
        }
    }

    private function afterLogin(ImapResponse $response): void
    {
        // Capabilities change after authentication (RFC 3501 6.2.3).
        if (!preg_match('/^\[CAPABILITY /i', $response->text)) {
            $this->refreshCapabilities();
        }
    }

    private function setCapabilities(string $list): void
    {
        $this->capabilities = [];
        foreach (preg_split('/\s+/', trim($list)) as $cap) {
            if ($cap !== '') {
                $this->capabilities[strtoupper($cap)] = true;
            }
        }
    }

    /** One logical response line, CRLF stripped, literals inline as "{n}\r\n<bytes>". */
    private function readResponse(): string
    {
        $buffer = '';
        while (true) {
            $line = $this->readLine();
            if (preg_match('/\{(\d+)\+?\}$/', $line, $m)) {
                $n = (int)$m[1];
                if ($n > self::MAX_LITERAL) {
                    $this->disconnect();
                    throw new ImapException('Odpowiedź serwera IMAP jest za duża (' . $n . ' B)');
                }
                $buffer .= $line . "\r\n" . $this->readBytes($n);
                if (strlen($buffer) > self::MAX_LINE + self::MAX_LITERAL) {
                    $this->disconnect();
                    throw new ImapException('Odpowiedź serwera IMAP jest za duża');
                }
                continue;
            }
            return $buffer . $line;
        }
    }

    private function readLine(): string
    {
        $line = '';
        while (true) {
            $chunk = fgets($this->stream, 65536);
            if ($chunk === false) {
                $this->failRead();
            }
            $line .= $chunk;
            if (str_ends_with($line, "\n")) {
                return rtrim($line, "\r\n");
            }
            if (strlen($line) > self::MAX_LINE) {
                $this->disconnect();
                throw new ImapException('Linia odpowiedzi serwera IMAP jest za długa');
            }
        }
    }

    private function readBytes(int $n): string
    {
        $data = '';
        while (strlen($data) < $n) {
            $chunk = fread($this->stream, min(1048576, $n - strlen($data)));
            if ($chunk === false || $chunk === '') {
                $this->failRead();
            }
            $data .= $chunk;
        }
        return $data;
    }

    private function failRead(): never
    {
        $meta = is_resource($this->stream) ? stream_get_meta_data($this->stream) : [];
        $this->disconnect();
        if (!empty($meta['timed_out'])) {
            throw new ImapException('Serwer IMAP nie odpowiedział w ciągu ' . $this->timeout . ' s');
        }
        throw new ImapException('Serwer IMAP zamknął połączenie');
    }

    private function write(string $data): void
    {
        $length = strlen($data);
        $written = 0;
        while ($written < $length) {
            $n = @fwrite($this->stream, substr($data, $written, 1048576));
            if ($n === false || $n === 0) {
                $this->disconnect();
                throw new ImapException('Nie można wysłać danych do serwera IMAP');
            }
            $written += $n;
        }
    }

    // ---- encoding ---------------------------------------------------------------

    /** IMAP quoted string; rejects CR, LF and NUL (they cannot be quoted). */
    public static function quote(string $value): string
    {
        if (preg_match('/[\r\n\x00]/', $value)) {
            throw new \InvalidArgumentException('Value cannot be sent as an IMAP quoted string');
        }
        return '"' . addcslashes($value, '"\\') . '"';
    }

    /** Mailbox name: UTF-8 -> modified UTF-7 (RFC 3501 5.1.3), quoted. */
    public static function quoteMailbox(string $name): string
    {
        $encoded = preg_match('/[^\x20-\x7e]/', $name) || str_contains($name, '&')
            ? mb_convert_encoding($name, 'UTF7-IMAP', 'UTF-8')
            : $name;
        return self::quote($encoded);
    }

    public static function decodeMailbox(string $name): string
    {
        if (!str_contains($name, '&')) {
            return $name;
        }
        $decoded = @mb_convert_encoding($name, 'UTF-8', 'UTF7-IMAP');
        return is_string($decoded) && $decoded !== '' ? $decoded : $name;
    }

    /** @param int[]|string $uids "1,5:7" or [1, 5, 6, 7] */
    public static function uidSet($uids): string
    {
        if (is_array($uids)) {
            $uids = array_values(array_unique(array_map('intval', $uids)));
            $uids = array_filter($uids, static fn ($u) => $u > 0);
            if (!$uids) {
                throw new \InvalidArgumentException('Empty UID set');
            }
            sort($uids, SORT_NUMERIC);
            return implode(',', $uids);
        }
        $set = str_replace(' ', '', (string)$uids);
        if (!preg_match('/^(\d+|\*)(:(\d+|\*))?(,(\d+|\*)(:(\d+|\*))?)*$/', $set)) {
            throw new \InvalidArgumentException('Invalid UID set');
        }
        return $set;
    }

    private static function clip(string $text): string
    {
        return mb_substr(mb_scrub($text, 'UTF-8'), 0, 300);
    }
}
