<?php

namespace AntispamBundle\Services;

/**
 * Minimal client for the ClamAV daemon (clamd), used to scan e-mail
 * attachments for malware via the INSTREAM command.
 *
 * The daemon is reached over a DSN that may be either a TCP endpoint
 * (`tcp://127.0.0.1:3310`, or the bare `host:port` shorthand) or a local
 * unix socket (`unix:///var/run/clamav/clamd.ctl`). All transport errors are
 * reported in the result rather than thrown, so a missing/unreachable daemon
 * never penalises a legitimate message — callers decide how to treat errors.
 */
class ClamavService
{
    const DEFAULT_DSN = 'tcp://127.0.0.1:3310';
    const DEFAULT_TIMEOUT = 30;

    // clamd reads INSTREAM in chunks; 8 KiB keeps memory flat and is well
    // under the daemon's StreamMaxLength chunk ceiling.
    const CHUNK_SIZE = 8192;

    /**
     * Scan a blob of bytes through clamd INSTREAM.
     *
     * @param string      $data    raw bytes to scan
     * @param string|null $dsn     clamd DSN (defaults to tcp://127.0.0.1:3310)
     * @param int         $timeout connect / read timeout in seconds
     *
     * @return array{clean: bool, signature: ?string, error: ?string}
     *               `clean` is true when the daemon reported the stream OK or
     *               when the scan could not be performed (see `error`).
     */
    public function scan($data, $dsn = null, $timeout = self::DEFAULT_TIMEOUT)
    {
        $remote = $this->normalizeDsn($dsn ?: self::DEFAULT_DSN);
        $timeout = $timeout > 0 ? (int)$timeout : self::DEFAULT_TIMEOUT;

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client($remote, $errno, $errstr, $timeout);
        if (!$socket) {
            return $this->fail(sprintf('cannot connect to clamd at %s: %s', $remote, $errstr ?: ('errno ' . $errno)));
        }
        stream_set_timeout($socket, $timeout);

        try {
            if (@fwrite($socket, "nINSTREAM\n") === false) {
                return $this->fail('failed to send INSTREAM command');
            }

            $len = strlen($data);
            for ($offset = 0; $offset < $len; $offset += self::CHUNK_SIZE) {
                $chunk = substr($data, $offset, self::CHUNK_SIZE);
                // Each chunk is prefixed with its length as a 4-byte
                // network-order (big-endian) unsigned integer.
                if (@fwrite($socket, pack('N', strlen($chunk)) . $chunk) === false) {
                    return $this->fail('failed while streaming data to clamd');
                }
            }
            // A zero-length chunk terminates the stream.
            @fwrite($socket, pack('N', 0));

            $response = '';
            while (!feof($socket)) {
                $buf = @fgets($socket, 4096);
                if ($buf === false) {
                    break;
                }
                $response .= $buf;
                $meta = stream_get_meta_data($socket);
                if (!empty($meta['timed_out'])) {
                    return $this->fail('timed out waiting for clamd response');
                }
            }
        } finally {
            @fclose($socket);
        }

        return $this->parseResponse($response);
    }

    /**
     * Liveness check: returns true when the daemon answers PING with PONG.
     */
    public function ping($dsn = null, $timeout = self::DEFAULT_TIMEOUT)
    {
        $remote = $this->normalizeDsn($dsn ?: self::DEFAULT_DSN);
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client($remote, $errno, $errstr, $timeout > 0 ? (int)$timeout : self::DEFAULT_TIMEOUT);
        if (!$socket) {
            return false;
        }
        stream_set_timeout($socket, $timeout > 0 ? (int)$timeout : self::DEFAULT_TIMEOUT);
        @fwrite($socket, "nPING\n");
        $response = trim((string)@fgets($socket, 64));
        @fclose($socket);
        return strtoupper($response) === 'PONG';
    }

    private function parseResponse($response)
    {
        $response = trim((string)$response);
        if ($response === '') {
            return $this->fail('empty response from clamd');
        }

        if (preg_match('/\bFOUND\b/', $response)) {
            $signature = 'unknown';
            // Typical reply: "stream: Eicar-Test-Signature FOUND"
            if (preg_match('/:\s*(.+?)\s+FOUND\b/', $response, $m)) {
                $signature = trim($m[1]);
            }
            return ['clean' => false, 'signature' => $signature, 'error' => null];
        }

        if (stripos($response, 'ERROR') !== false) {
            return $this->fail($response);
        }

        // "stream: OK"
        return ['clean' => true, 'signature' => null, 'error' => null];
    }

    /**
     * Accept the bare `host:port` shorthand alongside explicit tcp:// and
     * unix:// DSNs that stream_socket_client understands natively.
     */
    private function normalizeDsn($dsn)
    {
        $dsn = trim((string)$dsn);
        if ($dsn === '') {
            return self::DEFAULT_DSN;
        }
        if (preg_match('#^(tcp|unix)://#i', $dsn)) {
            return $dsn;
        }
        return 'tcp://' . $dsn;
    }

    private function fail($message)
    {
        return ['clean' => true, 'signature' => null, 'error' => $message];
    }
}
