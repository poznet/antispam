<?php

namespace AntispamBundle\Services;

/**
 * Thin client for the VirusTotal v3 API. Only the file *hash lookup* endpoint
 * is used: we send the SHA-256 of an attachment and read back the aggregated
 * analysis verdict. The attachment bytes never leave the server — only the
 * hash is transmitted — which keeps the integration privacy-friendly and fast.
 *
 * All errors (missing key, network failure, rate limiting, unknown hash) are
 * reported in the result rather than thrown, so the scoring pipeline can treat
 * an unavailable service as "no opinion" instead of penalising a message.
 */
class VirusTotalService
{
    const API_BASE = 'https://www.virustotal.com/api/v3/files/';
    const DEFAULT_TIMEOUT = 15;

    /**
     * Look up a file by its SHA-256 (or any VirusTotal-accepted hash).
     *
     * @return array{found: bool, malicious: int, suspicious: int, total: int, error: ?string}
     *               `found` is false when the hash is unknown to VirusTotal or
     *               the lookup could not be performed (see `error`).
     */
    public function lookupHash($hash, $apiKey, $timeout = self::DEFAULT_TIMEOUT)
    {
        $miss = ['found' => false, 'malicious' => 0, 'suspicious' => 0, 'total' => 0, 'error' => null];

        $hash = trim((string)$hash);
        $apiKey = trim((string)$apiKey);
        if ($hash === '') {
            return array_merge($miss, ['error' => 'empty hash']);
        }
        if ($apiKey === '') {
            return array_merge($miss, ['error' => 'no VirusTotal API key configured']);
        }
        if (!function_exists('curl_init')) {
            return array_merge($miss, ['error' => 'php curl extension is not available']);
        }

        $timeout = $timeout > 0 ? (int)$timeout : self::DEFAULT_TIMEOUT;

        $ch = curl_init(static::API_BASE . rawurlencode($hash));
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['x-apikey: ' . $apiKey, 'Accept: application/json'],
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            return array_merge($miss, ['error' => 'request failed: ' . $curlErr]);
        }

        // 404 = hash never seen by VirusTotal: a clean "not found", not an error.
        if ($status === 404) {
            return $miss;
        }
        if ($status === 401 || $status === 403) {
            return array_merge($miss, ['error' => 'VirusTotal rejected the API key (HTTP ' . $status . ')']);
        }
        if ($status === 429) {
            return array_merge($miss, ['error' => 'VirusTotal rate limit reached (HTTP 429)']);
        }
        if ($status < 200 || $status >= 300) {
            return array_merge($miss, ['error' => 'unexpected VirusTotal response (HTTP ' . $status . ')']);
        }

        $data = json_decode($body, true);
        $stats = $data['data']['attributes']['last_analysis_stats'] ?? null;
        if (!is_array($stats)) {
            return array_merge($miss, ['error' => 'malformed VirusTotal response']);
        }

        $malicious = (int)($stats['malicious'] ?? 0);
        $suspicious = (int)($stats['suspicious'] ?? 0);
        $total = array_sum(array_map('intval', $stats));

        return [
            'found' => true,
            'malicious' => $malicious,
            'suspicious' => $suspicious,
            'total' => $total,
            'error' => null,
        ];
    }

    /**
     * Liveness/credential check: looks up the well-known EICAR test file hash.
     * Returns true when VirusTotal answers with a usable verdict.
     */
    public function ping($apiKey, $timeout = self::DEFAULT_TIMEOUT)
    {
        // SHA-256 of the EICAR test string — always present in VirusTotal.
        $eicar = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
        $r = $this->lookupHash($eicar, $apiKey, $timeout);
        return $r['error'] === null;
    }
}
