<?php
/**
 * Antispam Maildir Agent - standalone PHP script
 *
 * Operates directly on Maildir folders, no IMAP required. Implements the same
 * scoring pipeline as the web application:
 *
 *   1. Deduplication (checked table, message-id based)
 *   2. Whitelist (exact / wildcard / regex patterns)
 *   3. Blacklist (exact / wildcard / regex + score)
 *   4. Header heuristics (SPF/DKIM/DMARC, suspicious subject, ...)
 *   5. DNSBL lookup against configured zones (with per-zone TTL cache)
 *   6. Attachment scanning (ClamAV malware + VirusTotal reputation)
 *   7. Threshold decision -> move to .SPAM or .QUARANTINE
 *
 * Requirements: PHP 7.1+, SQLite3 extension, DNS resolution for DNSBL lookups.
 * Optional: a reachable clamd for ClamAV scanning, the curl extension for
 * VirusTotal lookups. Both are off unless enabled in the synced settings.
 */

$defaultMaildir = getenv('HOME') . '/Maildir';
$defaultDb = __DIR__ . '/rules.sqlite';

// Manually parse CLI options - getopt() stops at the first positional argument,
// which breaks `agent.php scan --maildir=...`.
$command = $argv[1] ?? 'help';
$options = [];
for ($i = 2; $i < count($argv); $i++) {
    $arg = $argv[$i];
    if (strpos($arg, '--') !== 0) continue;
    $arg = substr($arg, 2);
    if (strpos($arg, '=') !== false) {
        list($k, $v) = explode('=', $arg, 2);
        $options[$k] = $v;
    } else {
        $options[$arg] = true;
    }
}
$maildirPath = $options['maildir'] ?? $defaultMaildir;
$dbPath = $options['db'] ?? $defaultDb;

// Defence-in-depth: refuse obvious path-traversal in CLI arguments. The agent
// runs as a constrained SSH user, but operators (or buggy callers) can still
// pass --maildir=../../etc and we'd silently mkdir() under that path below.
$maildirPath = sanitizePath($maildirPath, 'maildir');
$dbPath = sanitizePath($dbPath, 'db');

function sanitizePath($path, $label)
{
    $path = (string)$path;
    if ($path === '') {
        fwrite(STDERR, "Empty --{$label} path\n");
        exit(2);
    }
    if (strpos($path, "\0") !== false) {
        fwrite(STDERR, "Invalid --{$label} path (null byte)\n");
        exit(2);
    }
    // Reject relative-segment traversal both at start and embedded.
    $parts = preg_split('#[/\\\\]+#', $path);
    foreach ($parts as $p) {
        if ($p === '..') {
            fwrite(STDERR, "Invalid --{$label} path (contains '..')\n");
            exit(2);
        }
    }
    return $path;
}

switch ($command) {
    case 'test':
        echo json_encode(runTest($maildirPath), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'import-rules':
        echo json_encode(importRules($dbPath), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'scan':
        echo json_encode(runScan($maildirPath, $dbPath, $options), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'health':
        echo json_encode(runHealth($maildirPath, $dbPath), JSON_PRETTY_PRINT) . "\n";
        break;
    default:
        echo "Antispam Maildir Agent\n";
        echo "Usage:\n";
        echo "  php antispam-agent.php test\n";
        echo "  php antispam-agent.php import-rules < rules.json\n";
        echo "  php antispam-agent.php scan [--maildir=path] [--db=path] [--spam-threshold=N] [--quarantine-threshold=N] [--no-dnsbl] [--no-headers] [--no-clamav] [--no-virustotal]\n";
        echo "  php antispam-agent.php health [--maildir=path] [--db=path]\n";
        break;
}

/* ---------------------------------------------------------------------- */
/* Diagnostics                                                            */
/* ---------------------------------------------------------------------- */

function runTest($maildirPath)
{
    $result = ['success' => true, 'checks' => []];
    $result['checks']['php_version'] = PHP_VERSION;
    $result['checks']['sqlite3'] = extension_loaded('sqlite3') ? 'available' : 'NOT available';
    if (!extension_loaded('sqlite3')) { $result['success'] = false; }
    $result['checks']['dns_get_record'] = function_exists('dns_get_record') ? 'available' : 'missing (DNSBL will use gethostbyname fallback)';
    $result['checks']['curl'] = function_exists('curl_init') ? 'available' : 'missing (VirusTotal lookup disabled)';

    $result['checks']['maildir_path'] = $maildirPath;
    $result['checks']['maildir_exists'] = is_dir($maildirPath) ? 'yes' : 'no';
    $result['checks']['maildir_new'] = is_dir($maildirPath . '/new') ? 'yes' : 'no';
    $result['checks']['maildir_cur'] = is_dir($maildirPath . '/cur') ? 'yes' : 'no';
    $result['checks']['maildir_writable'] = is_writable($maildirPath) ? 'yes' : 'no';
    if (!is_dir($maildirPath)) { $result['success'] = false; }
    $result['checks']['agent_dir_writable'] = is_writable(__DIR__) ? 'yes' : 'no';
    return $result;
}

function runHealth($maildirPath, $dbPath)
{
    $out = [
        'agent_version' => '2.1',
        'php' => PHP_VERSION,
        'time' => date('c'),
        'maildir' => $maildirPath,
        'db' => $dbPath,
        'db_size_bytes' => file_exists($dbPath) ? filesize($dbPath) : 0,
    ];
    if (file_exists($dbPath)) {
        $db = getDb($dbPath);
        $out['rules'] = [
            'whitelist' => (int)$db->querySingle('SELECT COUNT(*) FROM whitelist'),
            'email_whitelist' => (int)$db->querySingle('SELECT COUNT(*) FROM email_whitelist'),
            'blacklist' => (int)$db->querySingle('SELECT COUNT(*) FROM blacklist'),
            'email_blacklist' => (int)$db->querySingle('SELECT COUNT(*) FROM email_blacklist'),
            'dnsbl_providers' => (int)$db->querySingle('SELECT COUNT(*) FROM dnsbl_providers WHERE enabled = 1'),
            'dnsbl_cache' => (int)$db->querySingle('SELECT COUNT(*) FROM dnsbl_cache'),
            'checked' => (int)$db->querySingle('SELECT COUNT(*) FROM checked'),
            'last_scan' => $db->querySingle('SELECT MAX(scanned_at) FROM scan_log'),
        ];
        $settings = loadSettings($db);
        $out['attachment_scanning'] = [
            'clamav_enabled' => !empty($settings['clamav_enabled']),
            'clamav_dsn' => $settings['clamav_dsn'] ?? null,
            'virustotal_enabled' => !empty($settings['vt_enabled']) && trim((string)($settings['vt_api_key'] ?? '')) !== '',
        ];
    }
    $out['maildir_new'] = countMessages($maildirPath, ['new']);
    $out['maildir_cur'] = countMessages($maildirPath, ['cur']);
    $out['maildir_spam'] = countMessages($maildirPath . '/.SPAM', ['new', 'cur']);
    $out['maildir_quarantine'] = countMessages($maildirPath . '/.QUARANTINE', ['new', 'cur']);
    return $out;
}

function countMessages($base, array $subdirs)
{
    $total = 0;
    foreach ($subdirs as $s) {
        $dir = $base . '/' . $s;
        if (is_dir($dir)) {
            $total += count(array_filter(glob($dir . '/*') ?: [], 'is_file'));
        }
    }
    return $total;
}

/* ---------------------------------------------------------------------- */
/* Rule import                                                            */
/* ---------------------------------------------------------------------- */

function importRules($dbPath)
{
    $input = file_get_contents('php://stdin');
    $data = json_decode($input, true);
    if (!$data) { return ['success' => false, 'error' => 'Invalid JSON input']; }

    $db = getDb($dbPath);

    $db->exec('DELETE FROM whitelist');
    $db->exec('DELETE FROM email_whitelist');
    $db->exec('DELETE FROM blacklist');
    $db->exec('DELETE FROM email_blacklist');
    $db->exec('DELETE FROM dnsbl_providers');

    $counts = [
        'whitelist' => 0, 'email_whitelist' => 0,
        'blacklist' => 0, 'email_blacklist' => 0,
        'dnsbl_providers' => 0, 'settings' => 0,
    ];

    if (!empty($data['whitelist'])) {
        $stmt = $db->prepare('INSERT INTO whitelist (email, host, pattern_type) VALUES (:email, :host, :pt)');
        foreach ($data['whitelist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':host', $row['host']);
            $stmt->bindValue(':pt', $row['pattern_type'] ?? 'exact');
            $stmt->execute();
            $counts['whitelist']++;
        }
    }
    if (!empty($data['email_whitelist'])) {
        $stmt = $db->prepare('INSERT INTO email_whitelist (email, whitelistemail, pattern_type) VALUES (:email, :w, :pt)');
        foreach ($data['email_whitelist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':w', $row['whitelistemail']);
            $stmt->bindValue(':pt', $row['pattern_type'] ?? 'exact');
            $stmt->execute();
            $counts['email_whitelist']++;
        }
    }
    if (!empty($data['blacklist'])) {
        $stmt = $db->prepare('INSERT INTO blacklist (email, host, pattern_type, score) VALUES (:email, :host, :pt, :sc)');
        foreach ($data['blacklist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':host', $row['host']);
            $stmt->bindValue(':pt', $row['pattern_type'] ?? 'exact');
            $stmt->bindValue(':sc', (int)($row['score'] ?? 10));
            $stmt->execute();
            $counts['blacklist']++;
        }
    }
    if (!empty($data['email_blacklist'])) {
        $stmt = $db->prepare('INSERT INTO email_blacklist (email, blacklistemail, pattern_type, score) VALUES (:email, :b, :pt, :sc)');
        foreach ($data['email_blacklist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':b', $row['blacklistemail']);
            $stmt->bindValue(':pt', $row['pattern_type'] ?? 'exact');
            $stmt->bindValue(':sc', (int)($row['score'] ?? 10));
            $stmt->execute();
            $counts['email_blacklist']++;
        }
    }
    if (!empty($data['dnsbl'])) {
        $stmt = $db->prepare('INSERT INTO dnsbl_providers (name, zone, score, enabled, cache_ttl) VALUES (:name, :zone, :score, :enabled, :ttl)');
        foreach ($data['dnsbl'] as $row) {
            $stmt->bindValue(':name', $row['name'] ?? $row['zone']);
            $stmt->bindValue(':zone', strtolower($row['zone']));
            $stmt->bindValue(':score', (int)($row['score'] ?? 5));
            $stmt->bindValue(':enabled', empty($row['enabled']) ? 0 : 1);
            $stmt->bindValue(':ttl', (int)($row['cache_ttl'] ?? 3600));
            $stmt->execute();
            $counts['dnsbl_providers']++;
        }
    }
    // Attachment-scanning settings (ClamAV / VirusTotal) pushed from the web UI.
    // Stored as key/value strings; booleans are normalised to '1'/'0'.
    if (isset($data['settings']) && is_array($data['settings'])) {
        $stmt = $db->prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (:k, :v)');
        foreach ($data['settings'] as $k => $v) {
            if (is_bool($v)) { $v = $v ? '1' : '0'; }
            $stmt->bindValue(':k', (string)$k);
            $stmt->bindValue(':v', (string)$v);
            $stmt->execute();
            $counts['settings']++;
        }
    }

    return ['success' => true, 'imported' => $counts];
}

/* ---------------------------------------------------------------------- */
/* Scan pipeline                                                          */
/* ---------------------------------------------------------------------- */

function runScan($maildirPath, $dbPath, $options = [])
{
    $spamThreshold = isset($options['spam-threshold']) ? (int)$options['spam-threshold'] : 10;
    $quarantineThreshold = isset($options['quarantine-threshold']) ? (int)$options['quarantine-threshold'] : 5;
    $dnsblEnabled = !isset($options['no-dnsbl']);
    $headerCheckEnabled = !isset($options['no-headers']);

    $db = getDb($dbPath);
    $settings = loadSettings($db);

    // Attachment scanning is driven by synced settings; CLI flags can force it off.
    $clamavEnabled = !isset($options['no-clamav']) && !empty($settings['clamav_enabled']);
    $vtEnabled = !isset($options['no-virustotal'])
        && !empty($settings['vt_enabled'])
        && trim((string)($settings['vt_api_key'] ?? '')) !== '';

    $stats = [
        'total' => 0, 'checked' => 0, 'skipped' => 0,
        'whitelisted' => 0, 'blacklisted' => 0,
        'quarantined' => 0, 'moved_to_spam' => 0,
        'attachments_flagged' => 0,
        'score_total' => 0,
        'decisions' => [],
    ];

    $whitelist = loadListRules($db, 'SELECT host, pattern_type FROM whitelist', 'host');
    $emailWhitelist = loadListRules($db, 'SELECT whitelistemail, pattern_type FROM email_whitelist', 'whitelistemail');
    $blacklist = loadListRules($db, 'SELECT host, pattern_type, score FROM blacklist', 'host');
    $emailBlacklist = loadListRules($db, 'SELECT blacklistemail, pattern_type, score FROM email_blacklist', 'blacklistemail');
    $dnsblProviders = [];
    if ($dnsblEnabled) {
        $res = $db->query('SELECT id, zone, score, cache_ttl FROM dnsbl_providers WHERE enabled = 1');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) { $dnsblProviders[] = $row; }
    }

    ensureFolder($maildirPath . '/.SPAM');
    ensureFolder($maildirPath . '/.QUARANTINE');

    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/' . $subdir;
        if (!is_dir($dir)) continue;

        foreach (scandir($dir) as $file) {
            if ($file === '.' || $file === '..') continue;
            $filePath = $dir . '/' . $file;
            if (!is_file($filePath)) continue;

            $stats['total']++;
            $baseId = preg_replace('/:2,[A-Z]*$/', '', basename($file));

            $stmt = $db->prepare('SELECT 1 FROM checked WHERE message_id = :id');
            $stmt->bindValue(':id', $baseId);
            if ($stmt->execute()->fetchArray()) { $stats['skipped']++; continue; }

            $stats['checked']++;

            $headers = readHeaderBlock($filePath);
            $parsed = parseHeaders($headers);
            $senderEmail = $parsed['sender_email'];
            $senderHost = $parsed['sender_host'];

            // Whitelist short-circuit
            if ($senderHost && matchList($whitelist, $senderHost)) {
                $stats['whitelisted']++;
                $stats['decisions'][] = ['file' => $file, 'decision' => 'whitelisted', 'score' => 0];
                markChecked($db, $baseId);
                logDecision($db, $senderEmail, $parsed['subject'], 0, 'whitelisted', []);
                continue;
            }
            if ($senderEmail && matchList($emailWhitelist, $senderEmail)) {
                $stats['whitelisted']++;
                $stats['decisions'][] = ['file' => $file, 'decision' => 'whitelisted', 'score' => 0];
                markChecked($db, $baseId);
                logDecision($db, $senderEmail, $parsed['subject'], 0, 'whitelisted', []);
                continue;
            }

            $score = 0;
            $reasons = [];
            $forceSpam = false;

            // Blacklist domain / email
            if ($senderHost) {
                $hit = matchListReturning($blacklist, $senderHost);
                if ($hit) {
                    $score += (int)$hit['score'];
                    $reasons[] = ['rule' => 'blacklist:' . $hit['value'], 'score' => (int)$hit['score']];
                }
            }
            if ($senderEmail) {
                $hit = matchListReturning($emailBlacklist, $senderEmail);
                if ($hit) {
                    $score += (int)$hit['score'];
                    $reasons[] = ['rule' => 'email_blacklist:' . $hit['value'], 'score' => (int)$hit['score']];
                }
            }

            // Header heuristics
            if ($headerCheckEnabled) {
                $hr = analyzeHeaders($headers);
                $score += $hr['score'];
                foreach ($hr['reasons'] as $r) { $reasons[] = $r; }
            }

            // DNSBL
            if ($dnsblProviders) {
                $ip = extractConnectingIp($headers);
                if ($ip) {
                    foreach ($dnsblProviders as $prov) {
                        if (dnsblLookup($db, $ip, $prov)) {
                            $score += (int)$prov['score'];
                            $reasons[] = ['rule' => 'dnsbl:' . $prov['zone'], 'score' => (int)$prov['score']];
                        }
                    }
                }
            }

            // Attachment scanning (ClamAV malware + VirusTotal reputation).
            // A hit adds the configured score and forces a spam decision. A
            // single flagged attachment is enough to condemn the message.
            if ($clamavEnabled || $vtEnabled) {
                $hit = scanAttachments($filePath, $settings, $clamavEnabled, $vtEnabled);
                if ($hit) {
                    $score += (int)$hit['score'];
                    $reasons[] = $hit['reason'];
                    $forceSpam = true;
                    $stats['attachments_flagged']++;
                }
            }

            $decision = 'ham';
            $targetDir = null;
            if ($forceSpam || $score >= $spamThreshold) {
                $decision = 'spam';
                $stats['blacklisted']++;
                $stats['moved_to_spam']++;
                $targetDir = $maildirPath . '/.SPAM/' . $subdir;
            } elseif ($score >= $quarantineThreshold) {
                $decision = 'quarantine';
                $stats['quarantined']++;
                $targetDir = $maildirPath . '/.QUARANTINE/' . $subdir;
            }

            if ($targetDir) {
                if (!is_dir($targetDir)) { mkdir($targetDir, 0755, true); }
                @rename($filePath, $targetDir . '/' . $file);
            }

            $stats['score_total'] += $score;
            $stats['decisions'][] = ['file' => $file, 'decision' => $decision, 'score' => $score];
            logDecision($db, $senderEmail, $parsed['subject'], $score, $decision, $reasons);
            markChecked($db, $baseId);
        }
    }

    // scan_log entry for "last scan" health reporting
    $stmt = $db->prepare('INSERT INTO scan_log (scanned_at, total, checked, moved_to_spam, quarantined) VALUES (:t, :tot, :ch, :sp, :q)');
    $stmt->bindValue(':t', date('c'));
    $stmt->bindValue(':tot', $stats['total']);
    $stmt->bindValue(':ch', $stats['checked']);
    $stmt->bindValue(':sp', $stats['moved_to_spam']);
    $stmt->bindValue(':q', $stats['quarantined']);
    $stmt->execute();

    // keep response small - don't return per-message decisions when huge
    if (count($stats['decisions']) > 200) {
        $stats['decisions'] = array_slice($stats['decisions'], 0, 200);
        $stats['decisions_truncated'] = true;
    }

    return $stats;
}

/* ---------------------------------------------------------------------- */
/* Pattern matching                                                       */
/* ---------------------------------------------------------------------- */

function loadListRules($db, $query, $valueCol)
{
    $rules = [];
    $res = $db->query($query);
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        $rules[] = [
            'value' => strtolower($row[$valueCol]),
            'pattern_type' => $row['pattern_type'] ?? 'exact',
            'score' => isset($row['score']) ? (int)$row['score'] : 0,
        ];
    }
    return $rules;
}

function matchList(array $rules, $value)
{
    return matchListReturning($rules, $value) !== null;
}

function matchListReturning(array $rules, $value)
{
    $value = strtolower((string)$value);
    foreach ($rules as $r) {
        if (patternMatch($r['value'], $value, $r['pattern_type'])) {
            return $r;
        }
    }
    return null;
}

function patternMatch($pattern, $value, $type)
{
    switch ($type) {
        case 'regex':
            $regex = '~' . str_replace('~', '\~', $pattern) . '~i';
            $ok = @preg_match($regex, $value);
            return $ok === 1;
        case 'wildcard':
            $regex = '~^' . globToRegex($pattern) . '$~i';
            return @preg_match($regex, $value) === 1;
        case 'exact':
        default:
            return $pattern === $value;
    }
}

function globToRegex($glob)
{
    $out = '';
    $len = strlen($glob);
    for ($i = 0; $i < $len; $i++) {
        $c = $glob[$i];
        switch ($c) {
            case '*': $out .= '.*'; break;
            case '?': $out .= '.'; break;
            case '.': case '\\': case '+': case '(': case ')':
            case '[': case ']': case '{': case '}': case '^': case '$':
            case '|': case '/':
                $out .= '\\' . $c;
                break;
            default: $out .= $c;
        }
    }
    return $out;
}

/* ---------------------------------------------------------------------- */
/* Header analysis                                                        */
/* ---------------------------------------------------------------------- */

function readHeaderBlock($filePath)
{
    $handle = @fopen($filePath, 'r');
    if (!$handle) return '';
    $block = '';
    while (($line = fgets($handle)) !== false) {
        if (trim($line) === '') break;
        $block .= $line;
    }
    fclose($handle);
    return $block;
}

function parseHeaders($block)
{
    $result = ['sender_email' => '', 'sender_host' => '', 'subject' => ''];
    if (preg_match('/^From:\s*.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/mi', $block, $m)) {
        $result['sender_email'] = strtolower($m[1]);
    } elseif (preg_match('/^Sender:\s*.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/mi', $block, $m)) {
        $result['sender_email'] = strtolower($m[1]);
    }
    if ($result['sender_email']) {
        $parts = explode('@', $result['sender_email']);
        $result['sender_host'] = $parts[1] ?? '';
    }
    if (preg_match('/^Subject:\s*(.+)$/mi', $block, $m)) {
        $result['subject'] = trim($m[1]);
    }
    return $result;
}

function analyzeHeaders($block)
{
    $score = 0;
    $reasons = [];
    $block = (string)$block;

    $auth = strtolower(grabHeader($block, 'Authentication-Results'));
    $spf = strtolower(grabHeader($block, 'Received-SPF'));

    if (preg_match('/spf=(fail|softfail)/', $auth) || strpos($spf, 'fail') === 0) {
        $score += 6; $reasons[] = ['rule' => 'spf_fail', 'score' => 6];
    }
    if (preg_match('/dkim=(fail|none)/', $auth)) {
        $score += 4; $reasons[] = ['rule' => 'dkim_fail', 'score' => 4];
    }
    if (preg_match('/dmarc=(fail|none)/', $auth)) {
        $score += 6; $reasons[] = ['rule' => 'dmarc_fail', 'score' => 6];
    }

    $from = extractEmail(grabHeader($block, 'From'));
    $reply = extractEmail(grabHeader($block, 'Reply-To'));
    if ($from && $reply && domainOf($from) !== domainOf($reply)) {
        $score += 3; $reasons[] = ['rule' => 'from_reply_mismatch', 'score' => 3];
    }

    $subject = grabHeader($block, 'Subject');
    if ($subject) {
        if (strlen($subject) > 8 && mb_strtoupper($subject, 'UTF-8') === $subject) {
            $score += 3; $reasons[] = ['rule' => 'all_caps_subject', 'score' => 3];
        } elseif (preg_match('/\${2,}|!{3,}|\?{3,}/', $subject)) {
            $score += 3; $reasons[] = ['rule' => 'suspicious_subject', 'score' => 3];
        } elseif (preg_match('/\b(viagra|cialis|lottery|winner|bitcoin|crypto airdrop|nigerian prince)\b/i', $subject)) {
            $score += 3; $reasons[] = ['rule' => 'suspicious_subject', 'score' => 3];
        }
    }

    if (!grabHeader($block, 'Message-ID')) {
        $score += 2; $reasons[] = ['rule' => 'missing_message_id', 'score' => 2];
    }

    $receivedCount = preg_match_all('/^Received:/mi', $block);
    if ($receivedCount > 10) {
        $score += 2; $reasons[] = ['rule' => 'many_received_hops', 'score' => 2];
    }

    return ['score' => $score, 'reasons' => $reasons];
}

function grabHeader($block, $name)
{
    if (preg_match('/^' . preg_quote($name, '/') . ':\s*(.+)$/mi', $block, $m)) {
        return trim($m[1]);
    }
    return '';
}

function extractEmail($line)
{
    if (preg_match('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', (string)$line, $m)) {
        return strtolower($m[0]);
    }
    return '';
}

function domainOf($email)
{
    $p = explode('@', strtolower((string)$email));
    return $p[1] ?? '';
}

/* ---------------------------------------------------------------------- */
/* DNSBL                                                                  */
/* ---------------------------------------------------------------------- */

function extractConnectingIp($headerBlock)
{
    if (preg_match_all('/^Received:.+$/mi', $headerBlock, $m)) {
        foreach ($m[0] as $line) {
            if (preg_match('/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', $line, $ipm)) {
                return $ipm[1];
            }
        }
        foreach ($m[0] as $line) {
            if (preg_match('/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/', $line, $ipm)) {
                return $ipm[1];
            }
        }
    }
    return null;
}

function dnsblLookup($db, $ip, $provider)
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    $zone = $provider['zone'];
    $ttl = max(60, (int)$provider['cache_ttl']);

    $stmt = $db->prepare('SELECT listed, checked_at FROM dnsbl_cache WHERE ip = :ip AND zone = :zone');
    $stmt->bindValue(':ip', $ip);
    $stmt->bindValue(':zone', $zone);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($row && (time() - strtotime($row['checked_at'])) < $ttl) {
        return (bool)$row['listed'];
    }

    $reverse = implode('.', array_reverse(explode('.', $ip)));
    $query = $reverse . '.' . $zone;

    $listed = false;
    if (function_exists('dns_get_record')) {
        $records = @dns_get_record($query, DNS_A);
        $listed = is_array($records) && count($records) > 0;
    } else {
        $resolved = @gethostbyname($query);
        $listed = $resolved && $resolved !== $query && filter_var($resolved, FILTER_VALIDATE_IP);
    }

    $upsert = $db->prepare('INSERT OR REPLACE INTO dnsbl_cache (ip, zone, listed, checked_at) VALUES (:ip, :zone, :listed, :t)');
    $upsert->bindValue(':ip', $ip);
    $upsert->bindValue(':zone', $zone);
    $upsert->bindValue(':listed', $listed ? 1 : 0);
    $upsert->bindValue(':t', date('c'));
    $upsert->execute();

    return $listed;
}

/* ---------------------------------------------------------------------- */
/* Attachment scanning (ClamAV + VirusTotal)                              */
/* ---------------------------------------------------------------------- */

function loadSettings($db)
{
    $settings = [];
    $res = @$db->query('SELECT key, value FROM settings');
    if ($res) {
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $settings[$row['key']] = $row['value'];
        }
    }
    return $settings;
}

/**
 * Scan a message file's attachments. Returns the first hit as
 * ['score' => int, 'reason' => [...]] or null when everything is clean / the
 * scan could not be performed (an unreachable daemon never condemns a message).
 */
function scanAttachments($filePath, array $settings, $clamavEnabled, $vtEnabled)
{
    $attachments = extractAttachments($filePath);
    if (!$attachments) {
        return null;
    }

    $clamavMaxSize = (int)($settings['clamav_max_size'] ?? 26214400);

    foreach ($attachments as $att) {
        $data = $att['data'];
        if ($data === '') {
            continue;
        }

        if ($clamavEnabled && ($clamavMaxSize <= 0 || strlen($data) <= $clamavMaxSize)) {
            $res = clamavScan(
                $data,
                $settings['clamav_dsn'] ?? 'tcp://127.0.0.1:3310',
                (int)($settings['clamav_timeout'] ?? 30)
            );
            if (!empty($res['infected'])) {
                $score = (int)($settings['clamav_score'] ?? 15);
                return ['score' => $score, 'reason' => [
                    'rule' => 'clamav:' . ($res['signature'] ?: 'unknown'),
                    'score' => $score,
                    'filename' => $att['filename'],
                ]];
            }
        }

        if ($vtEnabled) {
            $res = virusTotalLookup(
                hash('sha256', $data),
                (string)($settings['vt_api_key'] ?? ''),
                (int)($settings['vt_timeout'] ?? 15)
            );
            $threshold = max(1, (int)($settings['vt_threshold'] ?? 3));
            if (!empty($res['found']) && $res['malicious'] >= $threshold) {
                $score = (int)($settings['vt_score'] ?? 15);
                return ['score' => $score, 'reason' => [
                    'rule' => 'virustotal:' . $res['malicious'] . '/' . $res['total'],
                    'score' => $score,
                    'filename' => $att['filename'],
                ]];
            }
        }
    }

    return null;
}

/**
 * Extract decoded attachment parts from a raw Maildir message file.
 *
 * @return array list of ['filename' => string, 'data' => string]
 */
function extractAttachments($filePath)
{
    $raw = @file_get_contents($filePath);
    if ($raw === false || $raw === '') {
        return [];
    }
    $split = preg_split("/\r?\n\r?\n/", $raw, 2);
    if (count($split) < 2) {
        return [];
    }
    return walkMimePart($split[0], $split[1]);
}

function walkMimePart($headerBlock, $body)
{
    $contentType = grabHeaderFolded($headerBlock, 'Content-Type');
    $disposition = grabHeaderFolded($headerBlock, 'Content-Disposition');
    $encoding = strtolower(grabHeaderFolded($headerBlock, 'Content-Transfer-Encoding'));

    if (stripos($contentType, 'multipart/') === 0
        && preg_match('/boundary\s*=\s*"?([^";\r\n]+)"?/i', $contentType, $bm)) {
        $attachments = [];
        foreach (splitMultipart($body, $bm[1]) as $part) {
            $sub = preg_split("/\r?\n\r?\n/", $part, 2);
            if (count($sub) < 2) {
                continue;
            }
            $attachments = array_merge($attachments, walkMimePart($sub[0], $sub[1]));
        }
        return $attachments;
    }

    // Leaf part: treat it as an attachment when it is explicitly dispositioned
    // as one, carries a filename, or is a non-text binary payload.
    $filename = mimeParamFilename($contentType, $disposition);
    $isAttachment = stripos($disposition, 'attachment') !== false
        || $filename !== ''
        || isBinaryContentType($contentType);
    if (!$isAttachment) {
        return [];
    }

    $data = decodeMimeBody($body, $encoding);
    if ($data === '') {
        return [];
    }
    return [['filename' => $filename, 'data' => $data]];
}

function splitMultipart($body, $boundary)
{
    $parts = [];
    $segments = explode('--' . $boundary, $body);
    foreach ($segments as $i => $seg) {
        if ($i === 0) {
            continue; // preamble before the first boundary
        }
        if (strpos($seg, '--') === 0) {
            break; // closing delimiter "--boundary--" -> epilogue follows
        }
        $seg = preg_replace('/^\r?\n/', '', $seg);
        $seg = preg_replace('/\r?\n$/', '', $seg);
        $parts[] = $seg;
    }
    return $parts;
}

function decodeMimeBody($body, $encoding)
{
    switch ($encoding) {
        case 'base64':
            return (string)base64_decode(preg_replace('/\s+/', '', $body), false);
        case 'quoted-printable':
            return quoted_printable_decode($body);
        default:
            return $body;
    }
}

function mimeParamFilename($contentType, $disposition)
{
    if (preg_match('/filename\*?\s*=\s*"?([^";\r\n]+)"?/i', $disposition, $m)) {
        return trim($m[1]);
    }
    if (preg_match('/name\*?\s*=\s*"?([^";\r\n]+)"?/i', $contentType, $m)) {
        return trim($m[1]);
    }
    return '';
}

function isBinaryContentType($ct)
{
    $ct = strtolower((string)$ct);
    if ($ct === '' || strpos($ct, 'text/') === 0 || strpos($ct, 'multipart/') === 0) {
        return false;
    }
    return strpos($ct, 'application/') === 0
        || strpos($ct, 'image/') === 0
        || strpos($ct, 'audio/') === 0
        || strpos($ct, 'video/') === 0;
}

/**
 * Unfold a (possibly multi-line) header value: RFC 5322 continuation lines
 * begin with whitespace and are joined into a single logical value.
 */
function grabHeaderFolded($block, $name)
{
    if (preg_match('/^' . preg_quote($name, '/') . ':\s*(.*(?:\r?\n[ \t].*)*)/mi', $block, $m)) {
        return trim(preg_replace('/\r?\n[ \t]+/', ' ', $m[1]));
    }
    return '';
}

/**
 * Scan a blob through clamd's INSTREAM command.
 *
 * @return array{infected: bool, signature: string, error: ?string}
 */
function clamavScan($data, $dsn, $timeout)
{
    $clean = ['infected' => false, 'signature' => '', 'error' => null];
    $remote = clamavNormalizeDsn($dsn);
    $timeout = $timeout > 0 ? (int)$timeout : 30;

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client($remote, $errno, $errstr, $timeout);
    if (!$sock) {
        return array_merge($clean, ['error' => "connect failed: " . ($errstr ?: "errno $errno")]);
    }
    stream_set_timeout($sock, $timeout);

    if (@fwrite($sock, "nINSTREAM\n") === false) {
        @fclose($sock);
        return array_merge($clean, ['error' => 'write failed']);
    }
    $len = strlen($data);
    for ($o = 0; $o < $len; $o += 8192) {
        $chunk = substr($data, $o, 8192);
        if (@fwrite($sock, pack('N', strlen($chunk)) . $chunk) === false) {
            @fclose($sock);
            return array_merge($clean, ['error' => 'stream failed']);
        }
    }
    @fwrite($sock, pack('N', 0));

    $resp = '';
    while (!feof($sock)) {
        $buf = @fgets($sock, 4096);
        if ($buf === false) {
            break;
        }
        $resp .= $buf;
        $meta = stream_get_meta_data($sock);
        if (!empty($meta['timed_out'])) {
            @fclose($sock);
            return array_merge($clean, ['error' => 'timeout']);
        }
    }
    @fclose($sock);

    $resp = trim($resp);
    if (preg_match('/\bFOUND\b/', $resp)) {
        $sig = 'unknown';
        if (preg_match('/:\s*(.+?)\s+FOUND\b/', $resp, $m)) {
            $sig = trim($m[1]);
        }
        return ['infected' => true, 'signature' => $sig, 'error' => null];
    }
    if (stripos($resp, 'ERROR') !== false) {
        return array_merge($clean, ['error' => $resp]);
    }
    return $clean;
}

function clamavNormalizeDsn($dsn)
{
    $dsn = trim((string)$dsn);
    if ($dsn === '') {
        return 'tcp://127.0.0.1:3310';
    }
    if (preg_match('#^(tcp|unix)://#i', $dsn)) {
        return $dsn;
    }
    return 'tcp://' . $dsn;
}

/**
 * Look up a file hash on the VirusTotal v3 API. Only the hash is transmitted.
 *
 * @return array{found: bool, malicious: int, total: int, error: ?string}
 */
function virusTotalLookup($hash, $apiKey, $timeout)
{
    $miss = ['found' => false, 'malicious' => 0, 'total' => 0, 'error' => null];
    if (!function_exists('curl_init')) {
        return array_merge($miss, ['error' => 'curl extension unavailable']);
    }
    $hash = trim((string)$hash);
    $apiKey = trim((string)$apiKey);
    if ($hash === '' || $apiKey === '') {
        return array_merge($miss, ['error' => 'missing hash or API key']);
    }
    $timeout = $timeout > 0 ? (int)$timeout : 15;

    $ch = curl_init('https://www.virustotal.com/api/v3/files/' . rawurlencode($hash));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['x-apikey: ' . $apiKey, 'Accept: application/json'],
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
    ]);
    $body = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false) {
        return array_merge($miss, ['error' => 'request failed']);
    }
    if ($status === 404) {
        return $miss; // unknown hash: no opinion
    }
    if ($status < 200 || $status >= 300) {
        return array_merge($miss, ['error' => "HTTP $status"]);
    }
    $data = json_decode($body, true);
    $stats = $data['data']['attributes']['last_analysis_stats'] ?? null;
    if (!is_array($stats)) {
        return array_merge($miss, ['error' => 'malformed response']);
    }
    return [
        'found' => true,
        'malicious' => (int)($stats['malicious'] ?? 0),
        'total' => array_sum(array_map('intval', $stats)),
        'error' => null,
    ];
}

/* ---------------------------------------------------------------------- */
/* Persistence helpers                                                    */
/* ---------------------------------------------------------------------- */

function markChecked($db, $messageId)
{
    $stmt = $db->prepare('INSERT OR IGNORE INTO checked (message_id) VALUES (:id)');
    $stmt->bindValue(':id', $messageId);
    $stmt->execute();
}

function logDecision($db, $sender, $subject, $score, $decision, $reasons)
{
    $stmt = $db->prepare('INSERT INTO score_log (sender, subject, score, decision, reasons, scored_at) VALUES (:s, :sub, :sc, :d, :r, :t)');
    $stmt->bindValue(':s', (string)$sender);
    $stmt->bindValue(':sub', substr((string)$subject, 0, 500));
    $stmt->bindValue(':sc', (int)$score);
    $stmt->bindValue(':d', $decision);
    $stmt->bindValue(':r', json_encode($reasons));
    $stmt->bindValue(':t', date('c'));
    $stmt->execute();
}

function ensureFolder($path)
{
    foreach (['new', 'cur', 'tmp'] as $sub) {
        $dir = $path . '/' . $sub;
        if (!is_dir($dir)) { @mkdir($dir, 0755, true); }
    }
}

function getDb($dbPath)
{
    $isNew = !file_exists($dbPath);
    $db = new \SQLite3($dbPath);
    $db->busyTimeout(5000);

    $db->exec('CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact")');
    $db->exec('CREATE TABLE IF NOT EXISTS email_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, whitelistemail TEXT, pattern_type TEXT DEFAULT "exact")');
    $db->exec('CREATE TABLE IF NOT EXISTS blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10)');
    $db->exec('CREATE TABLE IF NOT EXISTS email_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, blacklistemail TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10)');
    $db->exec('CREATE TABLE IF NOT EXISTS checked (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE)');
    $db->exec('CREATE TABLE IF NOT EXISTS dnsbl_providers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, zone TEXT UNIQUE, score INTEGER DEFAULT 5, enabled INTEGER DEFAULT 1, cache_ttl INTEGER DEFAULT 3600)');
    $db->exec('CREATE TABLE IF NOT EXISTS dnsbl_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, zone TEXT, listed INTEGER, checked_at TEXT, UNIQUE(ip, zone))');
    $db->exec('CREATE TABLE IF NOT EXISTS score_log (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, subject TEXT, score INTEGER, decision TEXT, reasons TEXT, scored_at TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS scan_log (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT, total INTEGER, checked INTEGER, moved_to_spam INTEGER, quarantined INTEGER)');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)');

    // pattern_type column may not exist on old agent databases; ALTER if needed.
    if (!$isNew) {
        foreach (['whitelist' => 'host', 'email_whitelist' => 'whitelistemail', 'blacklist' => 'host', 'email_blacklist' => 'blacklistemail'] as $table => $_col) {
            $cols = [];
            $res = $db->query("PRAGMA table_info({$table})");
            while ($row = $res->fetchArray(SQLITE3_ASSOC)) { $cols[] = $row['name']; }
            if (!in_array('pattern_type', $cols, true)) {
                @$db->exec("ALTER TABLE {$table} ADD COLUMN pattern_type TEXT DEFAULT 'exact'");
            }
            if (in_array($table, ['blacklist', 'email_blacklist'], true) && !in_array('score', $cols, true)) {
                @$db->exec("ALTER TABLE {$table} ADD COLUMN score INTEGER DEFAULT 10");
            }
        }
    }

    return $db;
}
