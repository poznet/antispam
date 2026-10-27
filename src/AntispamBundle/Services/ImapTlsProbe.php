<?php

namespace AntispamBundle\Services;

/**
 * Connection diagnostics for the account form: opens a socket to the IMAP
 * server the way the chosen encryption mode would (implicit TLS, STARTTLS or
 * plain), reports the negotiated TLS version/cipher, the server certificate
 * (subject, SANs, issuer, validity, hostname match, chain verification) and
 * the IMAP capabilities, and can then try a real login with the c-client
 * flags the account would use.
 */
class ImapTlsProbe
{
    public function __construct(private int $timeout = 8)
    {
    }

    /**
     * @return array{ok: bool, steps: list<array{status: string, label: string, detail?: string}>,
     *               tls: ?array, certificate: ?array, capabilities: list<string>, login: ?array}
     */
    public function probe($host, $port, $encryption, $validateCert = true, $login = null, $password = null, $flags = null)
    {
        $result = ['ok' => false, 'steps' => [], 'tls' => null, 'certificate' => null, 'capabilities' => [], 'login' => null];
        $host = trim((string)$host);
        $port = (int)$port;

        if ($host === '' || !preg_match('~^[A-Za-z0-9.\-:\[\]]+$~', $host)) {
            $this->step($result, 'error', 'Nieprawidłowy host IMAP');
            return $result;
        }
        if ($port < 1 || $port > 65535) {
            $this->step($result, 'error', 'Nieprawidłowy port');
            return $result;
        }
        if (!in_array($encryption, ImapFlags::ENCRYPTIONS, true)) {
            $encryption = ImapFlags::ENCRYPTION_SSL;
        }

        $ips = $this->resolve($host);
        if (!$ips) {
            $this->step($result, 'error', 'DNS: nie można rozwiązać nazwy ' . $host);
            return $result;
        }
        $this->step($result, 'ok', 'DNS: ' . $host, implode(', ', $ips));

        if ($encryption === ImapFlags::ENCRYPTION_SSL) {
            $ok = $this->probeImplicitTls($result, $host, $port, $validateCert);
        } else {
            $ok = $this->probePlain($result, $host, $port, $encryption, $validateCert);
        }

        if ($ok && $login !== null && $login !== '') {
            $result['login'] = $this->tryLogin($host, $port, (string)$flags, (string)$login, (string)$password);
            $this->step($result, $result['login']['ok'] ? 'ok' : 'error', 'Logowanie IMAP (' . $flags . ')', $result['login']['message']);
            $ok = $result['login']['ok'];
        }

        $result['ok'] = $ok;
        return $result;
    }

    /**
     * Tries the usual setups (993 + SSL/TLS, 143 + STARTTLS) and returns the
     * results plus the first one that works, preferring a valid certificate.
     */
    public function detect($host)
    {
        $candidates = [
            ['encryption' => ImapFlags::ENCRYPTION_SSL, 'port' => 993],
            ['encryption' => ImapFlags::ENCRYPTION_STARTTLS, 'port' => 143],
        ];
        $results = [];
        $recommended = null;
        foreach ($candidates as $c) {
            $r = $this->probe($host, $c['port'], $c['encryption'], false);
            $certValid = $r['certificate']['verified'] ?? false;
            $results[] = $c + ['ok' => $r['ok'], 'cert_valid' => $certValid, 'probe' => $r];
            if ($r['ok'] && ($recommended === null || ($certValid && !$recommended['validate_cert']))) {
                $recommended = $c + ['validate_cert' => $certValid];
            }
        }
        return ['results' => $results, 'recommended' => $recommended];
    }

    private function probeImplicitTls(array &$result, $host, $port, $validateCert)
    {
        $errno = 0;
        $errstr = '';
        $verified = true;
        $verifyError = null;

        $stream = $this->tlsConnect($host, $port, true, $errno, $errstr);
        if (!$stream) {
            $verified = false;
            $verifyError = $this->lastError($errstr);
            $stream = $this->tlsConnect($host, $port, false, $errno, $errstr);
        }
        if (!$stream) {
            $this->step($result, 'error', 'Połączenie SSL/TLS z ' . $host . ':' . $port . ' nie powiodło się',
                $this->lastError($errstr, 'handshake TLS nie powiódł się') . ($errno === 0 ? ' (czy serwer na tym porcie mówi TLS? Dla portu 143 wybierz STARTTLS)' : ''));
            return false;
        }

        stream_set_timeout($stream, $this->timeout);
        $this->step($result, 'ok', 'Połączenie TCP + handshake TLS: ' . $host . ':' . $port);
        $this->collectTls($result, $stream, $host, $verified, $verifyError);
        $certOk = $this->reportCertificate($result, $validateCert);

        $greeting = $this->readLine($stream);
        $greetOk = $this->reportGreeting($result, $greeting);
        if ($greetOk) {
            $result['capabilities'] = $this->capabilities($stream, $greeting);
        }
        fclose($stream);

        return $greetOk && $certOk;
    }

    private function probePlain(array &$result, $host, $port, $encryption, $validateCert)
    {
        $stream = $this->plainConnect($result, $host, $port);
        if (!$stream) {
            return false;
        }
        $greeting = $this->readLine($stream);
        if (!$this->reportGreeting($result, $greeting)) {
            fclose($stream);
            return false;
        }
        $caps = $this->capabilities($stream, $greeting);
        $result['capabilities'] = $caps;
        $hasStartTls = in_array('STARTTLS', $caps, true);

        if ($encryption === ImapFlags::ENCRYPTION_NONE) {
            fclose($stream);
            $this->step($result, 'warning', 'Połączenie bez szyfrowania',
                'Login i hasło będą przesyłane jawnym tekstem.' . ($hasStartTls ? ' Serwer obsługuje STARTTLS – lepiej go włączyć.' : ''));
            if (in_array('LOGINDISABLED', $caps, true)) {
                $this->step($result, 'error', 'Serwer blokuje logowanie bez szyfrowania (LOGINDISABLED)', 'Wybierz STARTTLS lub SSL/TLS.');
                return false;
            }
            return true;
        }

        if (!$hasStartTls) {
            fclose($stream);
            if ($encryption === ImapFlags::ENCRYPTION_AUTO) {
                $this->step($result, 'warning', 'Serwer nie oferuje STARTTLS – połączenie będzie nieszyfrowane');
                return true;
            }
            $this->step($result, 'error', 'Serwer nie oferuje STARTTLS', 'Spróbuj SSL/TLS na porcie 993.');
            return false;
        }
        $this->step($result, 'ok', 'Serwer oferuje STARTTLS');
        fclose($stream);

        // Verified attempt first; on failure reconnect without verification to show the certificate.
        $verified = true;
        $verifyError = null;
        $stream = $this->startTls($host, $port, true, $verifyError);
        if (!$stream) {
            $verified = false;
            $stream = $this->startTls($host, $port, false, $error);
            if (!$stream) {
                $this->step($result, 'error', 'Negocjacja STARTTLS nie powiodła się', (string)$error);
                return false;
            }
        }
        $this->step($result, 'ok', 'Handshake TLS po STARTTLS');
        $this->collectTls($result, $stream, $host, $verified, $verifyError);
        $certOk = $this->reportCertificate($result, $validateCert);
        fclose($stream);

        return $certOk;
    }

    /**
     * The OpenSSL reason (e.g. "certificate verify failed") only comes as a
     * PHP warning, so it is captured into $errstr.
     */
    private function tlsConnect($host, $port, $verify, &$errno, &$errstr)
    {
        $warnings = [];
        set_error_handler(function ($no, $msg) use (&$warnings) { $warnings[] = $msg; return true; });
        $stream = stream_socket_client('ssl://' . $host . ':' . $port, $errno, $errstr, $this->timeout,
            STREAM_CLIENT_CONNECT, $this->tlsContext($host, $verify));
        restore_error_handler();
        if (!$stream) {
            $errstr = $this->opensslReason($warnings) ?? $errstr;
        }
        return $stream;
    }

    private function opensslReason(array $warnings)
    {
        foreach ($warnings as $w) {
            if (preg_match('~OpenSSL Error messages:\s*(.+)$~s', $w, $m)) {
                return trim(preg_replace('~\s+~', ' ', $m[1]));
            }
        }
        return null;
    }

    private function startTls($host, $port, $verify, &$error)
    {
        $error = null;
        $discard = [];
        $stream = $this->plainConnect($discard, $host, $port);
        if (!$stream) {
            $error = 'Brak połączenia TCP';
            return null;
        }
        $this->readLine($stream);
        fwrite($stream, "a1 STARTTLS\r\n");
        $line = $this->readTagged($stream, 'a1');
        if (!preg_match('~^a1 OK~i', (string)$line)) {
            $error = 'Odpowiedź serwera: ' . trim((string)$line);
            fclose($stream);
            return null;
        }
        foreach ($this->tlsContextOptions($host, $verify) as $k => $v) {
            stream_context_set_option($stream, 'ssl', $k, $v);
        }
        $warnings = [];
        set_error_handler(function ($no, $msg) use (&$warnings) { $warnings[] = $msg; return true; });
        $ok = stream_socket_enable_crypto($stream, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        restore_error_handler();
        if ($ok !== true) {
            $error = $this->lastError($this->opensslReason($warnings) ?? (string)end($warnings));
            fclose($stream);
            return null;
        }
        return $stream;
    }

    private function plainConnect(array &$result, $host, $port)
    {
        $errno = 0;
        $errstr = '';
        $stream = @stream_socket_client('tcp://' . $host . ':' . $port, $errno, $errstr, $this->timeout);
        if (!$stream) {
            $this->step($result, 'error', 'Połączenie TCP z ' . $host . ':' . $port . ' nie powiodło się', $errstr ?: 'timeout');
            return null;
        }
        stream_set_timeout($stream, $this->timeout);
        $this->step($result, 'ok', 'Połączenie TCP: ' . $host . ':' . $port);
        return $stream;
    }

    private function collectTls(array &$result, $stream, $host, $verified, $verifyError)
    {
        $meta = stream_get_meta_data($stream);
        $crypto = $meta['crypto'] ?? [];
        $result['tls'] = [
            'protocol' => $crypto['protocol'] ?? null,
            'cipher' => $crypto['cipher_name'] ?? null,
            'bits' => $crypto['cipher_bits'] ?? null,
        ];
        $params = stream_context_get_params($stream);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $result['certificate'] = $cert ? self::describeCertificate($cert, $host) : null;
        if ($result['certificate']) {
            $result['certificate']['verified'] = $verified;
            $result['certificate']['verify_error'] = $verifyError;
        }

        $protocol = (string)$result['tls']['protocol'];
        $legacy = in_array($protocol, ['SSLv3', 'TLSv1', 'TLSv1.0', 'TLSv1.1'], true);
        $this->step($result, $legacy ? 'warning' : 'ok', 'Protokół: ' . ($protocol ?: '?') . ', szyfr: ' . ($result['tls']['cipher'] ?: '?'),
            $legacy ? 'Przestarzała wersja TLS – serwer warto zaktualizować.' : null);
    }

    /**
     * @return bool false when validation is required and the certificate fails it
     */
    private function reportCertificate(array &$result, $validateCert)
    {
        $c = $result['certificate'];
        if (!$c) {
            $this->step($result, 'warning', 'Nie udało się odczytać certyfikatu serwera');
            return !$validateCert;
        }
        $problems = [];
        if ($c['expired']) { $problems[] = 'certyfikat wygasł ' . $c['valid_to']; }
        if ($c['not_yet_valid']) { $problems[] = 'certyfikat ważny dopiero od ' . $c['valid_from']; }
        if (!$c['hostname_match']) { $problems[] = 'nazwa hosta nie pasuje do certyfikatu (' . implode(', ', $c['names']) . ')'; }
        if ($c['self_signed']) { $problems[] = 'certyfikat samopodpisany'; }
        if (!$c['verified'] && !$problems) { $problems[] = 'nie można zweryfikować łańcucha: ' . $c['verify_error']; }

        if ($c['verified'] && !$problems) {
            $days = $c['days_left'];
            $this->step($result, $days < 14 ? 'warning' : 'ok', 'Certyfikat poprawny',
                $c['subject_cn'] . ', wystawca: ' . $c['issuer'] . ', ważny do ' . $c['valid_to'] . ' (' . $days . ' dni)');
            return true;
        }
        if ($validateCert) {
            $this->step($result, 'error', 'Certyfikat nie przeszedł weryfikacji', implode('; ', $problems)
                . '. Popraw certyfikat/nazwę hosta albo wybierz „Akceptuj każdy certyfikat”.');
            return false;
        }
        $this->step($result, 'warning', 'Certyfikat niezaufany – akceptowany, bo weryfikacja jest wyłączona', implode('; ', $problems));
        return true;
    }

    public static function describeCertificate($cert, $host)
    {
        $info = openssl_x509_parse($cert) ?: [];
        $names = [];
        foreach (explode(',', (string)($info['extensions']['subjectAltName'] ?? '')) as $san) {
            $san = trim($san);
            if (stripos($san, 'DNS:') === 0) {
                $names[] = strtolower(substr($san, 4));
            } elseif (stripos($san, 'IP Address:') === 0) {
                $names[] = trim(substr($san, 11));
            }
        }
        $cn = is_array($info['subject']['CN'] ?? null) ? end($info['subject']['CN']) : ($info['subject']['CN'] ?? '');
        if (!$names && $cn !== '') {
            $names[] = strtolower($cn);
        }
        $issuerParts = array_filter([
            is_array($info['issuer']['O'] ?? null) ? end($info['issuer']['O']) : ($info['issuer']['O'] ?? null),
            is_array($info['issuer']['CN'] ?? null) ? end($info['issuer']['CN']) : ($info['issuer']['CN'] ?? null),
        ]);
        $from = (int)($info['validFrom_time_t'] ?? 0);
        $to = (int)($info['validTo_time_t'] ?? 0);
        $now = time();

        return [
            'subject_cn' => $cn,
            'names' => $names,
            'issuer' => implode(' / ', $issuerParts),
            'valid_from' => $from ? date('Y-m-d', $from) : null,
            'valid_to' => $to ? date('Y-m-d', $to) : null,
            'days_left' => $to ? (int)floor(($to - $now) / 86400) : null,
            'expired' => $to && $to < $now,
            'not_yet_valid' => $from && $from > $now,
            'self_signed' => ($info['subject'] ?? null) === ($info['issuer'] ?? null),
            'hostname_match' => self::hostnameMatches($host, $names),
            'fingerprint' => openssl_x509_fingerprint($cert, 'sha256') ?: null,
            'verified' => false,
            'verify_error' => null,
        ];
    }

    public static function hostnameMatches($host, array $names)
    {
        $host = strtolower(trim($host, '[]'));
        foreach ($names as $name) {
            if ($name === $host) {
                return true;
            }
            // Wildcard covers exactly one label: *.example.com matches mail.example.com only.
            if (str_starts_with($name, '*.')) {
                $suffix = substr($name, 1);
                $label = substr($host, 0, -strlen($suffix));
                if (str_ends_with($host, $suffix) && $label !== '' && !str_contains($label, '.')) {
                    return true;
                }
            }
        }
        return false;
    }

    private function reportGreeting(array &$result, $greeting)
    {
        if (preg_match('~^\* (OK|PREAUTH)~i', (string)$greeting)) {
            $this->step($result, 'ok', 'Powitanie serwera IMAP', mb_substr(trim($greeting), 0, 160));
            return true;
        }
        $this->step($result, 'error', 'Serwer nie odpowiada jak serwer IMAP',
            $greeting === null ? 'brak odpowiedzi (timeout)' : mb_substr(trim($greeting), 0, 160));
        return false;
    }

    private function capabilities($stream, $greeting)
    {
        if (preg_match('~\[CAPABILITY ([^\]]+)\]~i', (string)$greeting, $m)) {
            return $this->splitCaps($m[1]);
        }
        fwrite($stream, "a0 CAPABILITY\r\n");
        $caps = [];
        for ($i = 0; $i < 20; $i++) {
            $line = $this->readLine($stream);
            if ($line === null) {
                break;
            }
            if (preg_match('~^\* CAPABILITY (.+)$~i', trim($line), $m)) {
                $caps = $this->splitCaps($m[1]);
            }
            if (str_starts_with($line, 'a0 ')) {
                break;
            }
        }
        return $caps;
    }

    private function splitCaps($caps)
    {
        return array_values(array_filter(array_map('strtoupper', preg_split('~\s+~', trim($caps)))));
    }

    private function readTagged($stream, $tag)
    {
        for ($i = 0; $i < 20; $i++) {
            $line = $this->readLine($stream);
            if ($line === null || str_starts_with($line, $tag . ' ')) {
                return $line;
            }
        }
        return null;
    }

    private function readLine($stream)
    {
        $line = @fgets($stream, 4096);
        return $line === false ? null : $line;
    }

    private function tryLogin($host, $port, $flags, $login, $password)
    {
        if (!function_exists('imap_open')) {
            return ['ok' => false, 'message' => 'Brak rozszerzenia PHP imap na tym serwerze – nie można sprawdzić logowania'];
        }
        try {
            $server = new \Ddeboer\Imap\Server($host, (string)$port, $flags ?: ImapFlags::DEFAULT_FLAGS);
            $connection = $server->authenticate($login, $password);
            $count = count($connection->getMailboxes());
            $connection->close();
            return ['ok' => true, 'message' => 'Zalogowano, folderów: ' . $count];
        } catch (\Throwable $e) {
            return ['ok' => false, 'message' => $e->getMessage()];
        }
    }

    private function resolve($host)
    {
        $bare = trim($host, '[]');
        if (filter_var($bare, FILTER_VALIDATE_IP)) {
            return [$bare];
        }
        $ips = [];
        foreach ((@dns_get_record($host, DNS_A | DNS_AAAA) ?: []) as $r) {
            $ips[] = $r['ip'] ?? $r['ipv6'] ?? null;
        }
        $ips = array_values(array_filter($ips));
        if (!$ips) {
            $ip = gethostbyname($host);
            if ($ip !== $host) {
                $ips[] = $ip;
            }
        }
        return $ips;
    }

    private function tlsContext($host, $verify)
    {
        return stream_context_create(['ssl' => $this->tlsContextOptions($host, $verify)]);
    }

    private function tlsContextOptions($host, $verify)
    {
        return [
            'verify_peer' => $verify,
            'verify_peer_name' => $verify,
            'allow_self_signed' => !$verify,
            'peer_name' => trim($host, '[]'),
            'SNI_enabled' => true,
            'capture_peer_cert' => true,
        ];
    }

    private function lastError($fallback, $default = 'nieznany błąd')
    {
        $messages = [];
        while ($msg = openssl_error_string()) {
            $messages[] = $msg;
        }
        $text = trim(($fallback ? $fallback . ' ' : '') . implode('; ', $messages));
        return $text !== '' ? $text : $default;
    }

    private function step(array &$result, $status, $label, $detail = null)
    {
        $result['steps'][] = array_filter(['status' => $status, 'label' => $label, 'detail' => $detail], fn ($v) => $v !== null && $v !== '');
    }
}
