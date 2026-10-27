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
 *   5. Impersonation / BEC (VIP display names, lookalike domains, own-domain spoofing)
 *   6. DNSBL lookup against configured zones (with per-zone TTL cache)
 *   7. Link protection (URL heuristics, URI block lists, Safe Browsing)
 *   8. Attachment policy (blocked types, double extensions, macros, encrypted archives)
 *   9. Attachment scanning (ClamAV malware + VirusTotal reputation)
 *  10. Threshold decision -> move to .SPAM or .QUARANTINE
 *
 * It also manages the quarantine for the end-user digest: list, release (with
 * optional sender whitelisting) and delete quarantined messages.
 *
 * Requirements: PHP 7.1+, SQLite3 extension, DNS resolution for DNSBL lookups.
 * Optional: a reachable clamd for ClamAV scanning, the curl extension for
 * VirusTotal lookups. Both are off unless enabled in the synced settings.
 */

// Test suites include this file to check it against the web application's
// analyzers; top-level functions stay defined after this early return.
if (defined('ANTISPAM_AGENT_LIBRARY')) {
    return;
}

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
$maildirPath = agentPath($options['maildir'] ?? $defaultMaildir, 'maildir');
$dbPath = agentPath($options['db'] ?? $defaultDb, 'db');

/**
 * Validates a --maildir / --db path: no empty value, NUL byte or ".."
 * segment. A leading "~/" (not expanded by the shell after "--x=") is
 * resolved against $HOME.
 */
function agentPath($path, $label)
{
    $path = (string)$path;
    if ($path === '~' || strncmp($path, '~/', 2) === 0) {
        $path = getenv('HOME') . substr($path, 1);
    }
    if ($path === '' || strpos($path, "\0") !== false || in_array('..', preg_split('#[/\\\\]+#', $path), true)) {
        fwrite(STDERR, "Invalid --{$label} path\n");
        exit(2);
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
    case 'quarantine-list':
        echo json_encode(quarantineList($maildirPath, $dbPath, $options), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'quarantine-release':
        echo json_encode(quarantineRelease($maildirPath, $dbPath, $options), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'quarantine-delete':
        echo json_encode(quarantineDelete($maildirPath, $dbPath, $options), JSON_PRETTY_PRINT) . "\n";
        break;
    default:
        echo "Antispam Maildir Agent\n";
        echo "Usage:\n";
        echo "  php antispam-agent.php test\n";
        echo "  php antispam-agent.php import-rules < rules.json\n";
        echo "  php antispam-agent.php scan [--maildir=path] [--db=path] [--spam-threshold=N] [--quarantine-threshold=N] [--no-dnsbl] [--no-headers] [--no-impersonation] [--no-urls] [--no-attachment-policy] [--no-clamav] [--no-virustotal]\n";
        echo "  php antispam-agent.php health [--maildir=path] [--db=path]\n";
        echo "  php antispam-agent.php quarantine-list [--maildir=path] [--db=path] [--since=unix-ts] [--limit=N]\n";
        echo "  php antispam-agent.php quarantine-release --id=ID [--whitelist] [--maildir=path] [--db=path]\n";
        echo "  php antispam-agent.php quarantine-delete --id=ID [--maildir=path] [--db=path]\n";
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
        'agent_version' => '2.2',
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
            'policy_enabled' => settingBool($settings, 'attachment_policy_enabled', true),
        ];
        $out['protection'] = [
            'impersonation_enabled' => settingBool($settings, 'impersonation_enabled', true),
            'protected_domains' => array_values(array_filter(preg_split('/\s+/', (string)($settings['impersonation_protected_domains'] ?? '')))),
            'url_enabled' => settingBool($settings, 'url_enabled', true),
            'url_dbl_enabled' => settingBool($settings, 'url_dbl_enabled', true),
            'safebrowsing_enabled' => settingBool($settings, 'url_gsb_enabled', false) && trim((string)($settings['url_gsb_api_key'] ?? '')) !== '',
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
    $impersonationEnabled = !isset($options['no-impersonation']) && settingBool($settings, 'impersonation_enabled', true);
    $urlEnabled = !isset($options['no-urls']) && settingBool($settings, 'url_enabled', true);
    $policyEnabled = !isset($options['no-attachment-policy']) && settingBool($settings, 'attachment_policy_enabled', true);

    $protectedDomains = array_values(array_filter(preg_split('/\s+/', strtolower((string)($settings['impersonation_protected_domains'] ?? '')))));
    $vips = parseVips((string)($settings['impersonation_vips'] ?? ''));
    $urlConfig = urlConfigFromSettings($settings);
    $policyConfig = policyConfigFromSettings($settings);
    $dblCache = [];

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
                logDecision($db, $senderEmail, $parsed['subject'], 0, 'whitelisted', [], $baseId);
                continue;
            }
            if ($senderEmail && matchList($emailWhitelist, $senderEmail)) {
                $stats['whitelisted']++;
                $stats['decisions'][] = ['file' => $file, 'decision' => 'whitelisted', 'score' => 0];
                markChecked($db, $baseId);
                logDecision($db, $senderEmail, $parsed['subject'], 0, 'whitelisted', [], $baseId);
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

            // Impersonation / BEC
            if ($impersonationEnabled) {
                $from = parseFromHeader(grabHeaderFolded($headers, 'From'));
                $ir = analyzeImpersonation([
                    'from_name' => $from['name'],
                    'from_email' => $from['email'],
                    'auth_results' => grabHeaderFolded($headers, 'Authentication-Results'),
                ], $protectedDomains, $vips, $settings);
                $score += $ir['score'];
                foreach ($ir['reasons'] as $r) { $reasons[] = $r; }
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

            // Body + attachments are parsed once, only when a step needs them.
            $parts = null;
            if ($urlEnabled || $policyEnabled || $clamavEnabled || $vtEnabled) {
                $parts = parseMessageParts($filePath);
            }

            // Link protection
            if ($urlEnabled && ($parts['html'] !== '' || $parts['text'] !== '')) {
                $ur = analyzeUrls($parts['html'], $parts['text'], $urlConfig, $db, $dblCache);
                $score += $ur['score'];
                foreach ($ur['reasons'] as $r) { $reasons[] = $r; }
            }

            // Attachment policy (no daemon / API needed)
            if ($policyEnabled && $parts['attachments']) {
                $pr = analyzeAttachmentPolicy($parts['attachments'], $policyConfig);
                $score += $pr['score'];
                foreach ($pr['reasons'] as $r) { $reasons[] = $r; }
                if ($pr['score'] > 0) { $stats['attachments_flagged']++; }
            }

            // Attachment scanning (ClamAV malware + VirusTotal reputation).
            // A hit adds the configured score and forces a spam decision. A
            // single flagged attachment is enough to condemn the message.
            if (($clamavEnabled || $vtEnabled) && $parts['attachments']) {
                $hit = scanAttachments($parts['attachments'], $settings, $clamavEnabled, $vtEnabled);
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
            logDecision($db, $senderEmail, $parsed['subject'], $score, $decision, $reasons, $baseId);
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
function scanAttachments(array $attachments, array $settings, $clamavEnabled, $vtEnabled)
{
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
 * Parse a raw Maildir message file into decoded attachments and text bodies.
 *
 * @return array ['attachments' => [['filename' => string, 'data' => string]], 'html' => string, 'text' => string]
 */
function parseMessageParts($filePath)
{
    $out = ['attachments' => [], 'html' => '', 'text' => ''];
    $raw = @file_get_contents($filePath);
    if ($raw === false || $raw === '') {
        return $out;
    }
    $split = preg_split("/\r?\n\r?\n/", $raw, 2);
    if (count($split) < 2) {
        return $out;
    }
    $bodies = ['html' => '', 'text' => ''];
    $out['attachments'] = walkMimePart($split[0], $split[1], $bodies);
    $out['html'] = $bodies['html'];
    $out['text'] = $bodies['text'];
    return $out;
}

function walkMimePart($headerBlock, $body, &$bodies = null)
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
            $attachments = array_merge($attachments, walkMimePart($sub[0], $sub[1], $bodies));
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
        // Inline text body: keep it for link analysis (1 MiB cap per kind).
        if ($bodies !== null && preg_match('#^\s*(text/(html|plain))?#i', $contentType, $tm)) {
            $kind = (isset($tm[2]) && strtolower($tm[2]) === 'html') ? 'html' : 'text';
            if (strlen($bodies[$kind]) < 1048576) {
                $bodies[$kind] .= substr(decodeMimeBody($body, $encoding), 0, 1048576) . "\n";
            }
        }
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
/* Settings helpers                                                       */
/* ---------------------------------------------------------------------- */

function settingBool(array $settings, $key, $default)
{
    if (!isset($settings[$key]) || $settings[$key] === '') {
        return $default;
    }
    return in_array(strtolower((string)$settings[$key]), ['1', 'true', 'yes', 'on'], true);
}

function settingInt(array $settings, $key, $default)
{
    return (isset($settings[$key]) && $settings[$key] !== '') ? (int)$settings[$key] : $default;
}

/* ---------------------------------------------------------------------- */
/* Domain helpers (mirror AntispamBundle\Services\DomainHelper)           */
/* ---------------------------------------------------------------------- */

function domNormalize($domain)
{
    $domain = strtolower(trim((string)$domain, " \t\r\n.[]"));
    if (($p = strrpos($domain, '@')) !== false) {
        $domain = substr($domain, $p + 1);
    }
    return preg_replace('/:\d+$/', '', $domain);
}

function domIsIp($host)
{
    return (bool)filter_var(trim((string)$host, '[]'), FILTER_VALIDATE_IP);
}

function domRegistrable($domain)
{
    static $multi = [
        'com.pl', 'net.pl', 'org.pl', 'info.pl', 'biz.pl', 'edu.pl', 'gov.pl',
        'waw.pl', 'krakow.pl', 'wroclaw.pl', 'poznan.pl', 'gda.pl', 'katowice.pl',
        'lodz.pl', 'szczecin.pl', 'lublin.pl', 'slask.pl', 'com.de',
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
        'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp',
        'com.br', 'com.cn', 'com.tr', 'com.ua', 'com.mx', 'com.ar', 'co.za',
        'co.in', 'co.il', 'co.kr', 'com.sg', 'com.hk', 'com.tw', 'com.ru',
    ];
    $domain = domNormalize($domain);
    if ($domain === '' || domIsIp($domain)) {
        return $domain;
    }
    $labels = explode('.', $domain);
    $n = count($labels);
    if ($n <= 2) {
        return $domain;
    }
    $lastTwo = $labels[$n - 2] . '.' . $labels[$n - 1];
    return in_array($lastTwo, $multi, true) ? $labels[$n - 3] . '.' . $lastTwo : $lastTwo;
}

function domLabel($domain)
{
    $reg = domRegistrable($domain);
    $p = strpos($reg, '.');
    return $p === false ? $reg : substr($reg, 0, $p);
}

function domToUnicode($domain)
{
    $domain = domNormalize($domain);
    if (strpos($domain, 'xn--') === false || !function_exists('idn_to_utf8')) {
        return $domain;
    }
    $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
    $decoded = @idn_to_utf8($domain, 0, $variant);
    return $decoded ? $decoded : $domain;
}

function domSkeleton($label)
{
    $s = mb_strtolower(domToUnicode($label), 'UTF-8');
    $s = strtr($s, [
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'у' => 'y',
        'х' => 'x', 'і' => 'i', 'ј' => 'j', 'ѕ' => 's', 'һ' => 'h', 'ԁ' => 'd',
        'ӏ' => 'l', 'ԝ' => 'w', 'ο' => 'o', 'α' => 'a', 'ε' => 'e', 'ι' => 'i',
        'κ' => 'k', 'ν' => 'v', 'τ' => 't', 'υ' => 'u', 'ρ' => 'p',
        'ı' => 'i', 'ɩ' => 'i', 'ɑ' => 'a', 'ɡ' => 'g', 'ł' => 'l',
    ]);
    if (function_exists('transliterator_transliterate')) {
        $t = @transliterator_transliterate('Latin-ASCII', $s);
        if (is_string($t)) {
            $s = $t;
        }
    } else {
        $s = strtr($s, ['ą' => 'a', 'ć' => 'c', 'ę' => 'e', 'ń' => 'n', 'ó' => 'o', 'ś' => 's', 'ź' => 'z', 'ż' => 'z']);
    }
    return strtr($s, [
        '0' => 'o', '1' => 'l', '3' => 'e', '5' => 's', '$' => 's',
        'rn' => 'm', 'vv' => 'w', 'cl' => 'd', 'i' => 'l',
    ]);
}

function domDistance($a, $b)
{
    $a = preg_split('//u', (string)$a, -1, PREG_SPLIT_NO_EMPTY);
    $b = preg_split('//u', (string)$b, -1, PREG_SPLIT_NO_EMPTY);
    $la = count($a);
    $lb = count($b);
    if ($la === 0) return $lb;
    if ($lb === 0) return $la;
    // Optimal string alignment: a transposition ("frima") costs 1, like a typo.
    $d = [];
    for ($i = 0; $i <= $la; $i++) { $d[$i] = [$i]; }
    for ($j = 0; $j <= $lb; $j++) { $d[0][$j] = $j; }
    for ($i = 1; $i <= $la; $i++) {
        for ($j = 1; $j <= $lb; $j++) {
            $cost = $a[$i - 1] === $b[$j - 1] ? 0 : 1;
            $d[$i][$j] = min($d[$i - 1][$j] + 1, $d[$i][$j - 1] + 1, $d[$i - 1][$j - 1] + $cost);
            if ($i > 1 && $j > 1 && $a[$i - 1] === $b[$j - 2] && $a[$i - 2] === $b[$j - 1]) {
                $d[$i][$j] = min($d[$i][$j], $d[$i - 2][$j - 2] + 1);
            }
        }
    }
    return $d[$la][$lb];
}

/* ---------------------------------------------------------------------- */
/* Impersonation / BEC (mirror ImpersonationAnalyzer)                     */
/* ---------------------------------------------------------------------- */

function parseFromHeader($value)
{
    $value = trim((string)$value);
    $email = extractEmail($value);
    $name = '';
    if (($p = strpos($value, '<')) !== false) {
        $name = trim(substr($value, 0, $p));
    }
    if (strpos($name, '=?') !== false && function_exists('mb_decode_mimeheader')) {
        $name = mb_decode_mimeheader($name);
    }
    return ['name' => trim($name, " \t\"'"), 'email' => $email];
}

function normalizePersonName($name)
{
    $name = mb_strtolower(trim((string)$name, " \t\"'"), 'UTF-8');
    if ($name === '') {
        return '';
    }
    if (function_exists('transliterator_transliterate')) {
        $t = @transliterator_transliterate('Any-Latin; Latin-ASCII', $name);
        if ($t !== false && $t !== null) {
            $name = $t;
        }
    } else {
        $name = strtr($name, ['ą' => 'a', 'ć' => 'c', 'ę' => 'e', 'ł' => 'l', 'ń' => 'n', 'ó' => 'o', 'ś' => 's', 'ź' => 'z', 'ż' => 'z']);
    }
    $name = preg_replace('/[^a-z0-9@. ]+/', ' ', $name);
    return trim(preg_replace('/\s+/', ' ', $name));
}

function parseVips($text)
{
    $vips = [];
    foreach (preg_split('/\r?\n/', (string)$text) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        preg_match_all('/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', $line, $m);
        $emails = array_map('strtolower', $m[0]);
        $name = trim(preg_replace('/[<>(),]|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i', ' ', $line));
        $norm = normalizePersonName($name);
        if ($norm === '' || strpos($norm, ' ') === false) {
            continue;
        }
        $vips[] = ['name' => $norm, 'label' => $name, 'emails' => $emails];
    }
    return $vips;
}

function vipNameMatches($normName, $vipName)
{
    if (strpos(' ' . $normName . ' ', ' ' . $vipName . ' ') !== false) {
        return true;
    }
    $words = explode(' ', $normName);
    foreach (explode(' ', $vipName) as $w) {
        if (!in_array($w, $words, true)) {
            return false;
        }
    }
    return true;
}

function lookalikeReason($domain, $protectedReg)
{
    $domain = domNormalize($domain);
    $reg = domRegistrable($domain);
    if ($reg === $protectedReg || $reg === '') {
        return null;
    }
    $pLabel = domLabel($protectedReg);
    $dLabel = domLabel(domToUnicode($reg));
    if (mb_strlen($pLabel, 'UTF-8') < 4) {
        return null;
    }
    if (strpos($domain . '.', $protectedReg . '.') !== false) {
        return 'subdomain';
    }
    if ($dLabel === $pLabel) {
        return 'tld';
    }
    if (domSkeleton($dLabel) === domSkeleton($pLabel)) {
        return 'homoglyph';
    }
    if (preg_match('/(^|[-0-9])' . preg_quote($pLabel, '/') . '($|[-0-9])/', $dLabel)) {
        return 'affix';
    }
    $len = mb_strlen($pLabel, 'UTF-8');
    if ($len >= 5 && domDistance($dLabel, $pLabel) <= ($len >= 10 ? 2 : 1)) {
        return 'typo';
    }
    return null;
}

function analyzeImpersonation(array $msg, array $protectedDomains, array $vips, array $settings)
{
    $sVip = settingInt($settings, 'impersonation_vip_score', 8);
    $sLook = settingInt($settings, 'impersonation_lookalike_score', 6);
    $sEmb = settingInt($settings, 'impersonation_embedded_score', 3);
    $sInt = settingInt($settings, 'impersonation_internal_score', 6);

    $fromEmail = strtolower(trim((string)$msg['from_email']));
    $fromName = (string)$msg['from_name'];
    $fromDomain = domNormalize(substr(strrchr($fromEmail, '@') ?: '', 1));
    $auth = strtolower((string)$msg['auth_results']);
    $score = 0;
    $reasons = [];
    if ($fromEmail === '' || $fromDomain === '') {
        return ['score' => 0, 'reasons' => []];
    }

    $protectedRegs = [];
    foreach ($protectedDomains as $d) {
        $protectedRegs[domRegistrable($d)] = $d;
    }
    $fromIsProtected = isset($protectedRegs[domRegistrable($fromDomain)]);

    $normName = normalizePersonName($fromName);
    if ($normName !== '') {
        foreach ($vips as $vip) {
            if (!vipNameMatches($normName, $vip['name'])) {
                continue;
            }
            $legit = $vip['emails'] ? in_array($fromEmail, $vip['emails'], true) : $fromIsProtected;
            if (!$legit && $sVip > 0) {
                $score += $sVip;
                $reasons[] = ['rule' => 'impersonation_vip:' . $vip['label'], 'score' => $sVip, 'sender' => $fromEmail];
            }
            break;
        }
    }

    if (preg_match('/[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})/i', $fromName, $m) && strtolower($m[0]) !== $fromEmail) {
        if (isset($protectedRegs[domRegistrable($m[1])]) && !$fromIsProtected) {
            if ($sVip > 0) {
                $score += $sVip;
                $reasons[] = ['rule' => 'impersonation_display_address:' . strtolower($m[0]), 'score' => $sVip];
            }
        } elseif ($sEmb > 0) {
            $score += $sEmb;
            $reasons[] = ['rule' => 'display_name_embedded_address', 'score' => $sEmb];
        }
    }

    if (!$fromIsProtected && $sLook > 0) {
        foreach ($protectedRegs as $reg => $orig) {
            $why = lookalikeReason($fromDomain, $reg);
            if ($why !== null) {
                $score += $sLook;
                $reasons[] = ['rule' => 'lookalike_domain:' . $fromDomain . '~' . $reg, 'score' => $sLook, 'match' => $why];
                break;
            }
        }
    }

    if ($fromIsProtected && $sInt > 0 && (preg_match('/\bspf=(fail|softfail)\b/', $auth) || preg_match('/\bdmarc=fail\b/', $auth))) {
        $score += $sInt;
        $reasons[] = ['rule' => 'internal_domain_spoof:' . $fromDomain, 'score' => $sInt];
    }

    return ['score' => $score, 'reasons' => $reasons];
}

/* ---------------------------------------------------------------------- */
/* Link protection (mirror UrlAnalyzer)                                   */
/* ---------------------------------------------------------------------- */

function urlConfigFromSettings(array $settings)
{
    $zones = [];
    $rawZones = isset($settings['url_dbl_zones']) ? (string)$settings['url_dbl_zones'] : "dbl.spamhaus.org 6\nmulti.surbl.org 6";
    foreach (preg_split('/\r?\n/', $rawZones) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') {
            continue;
        }
        $parts = preg_split('/[\s|,;]+/', $line);
        $zone = strtolower(trim($parts[0], '.'));
        if (preg_match('/^[a-z0-9.\-]+\.[a-z]{2,}$/', $zone)) {
            $zones[] = ['zone' => $zone, 'score' => (isset($parts[1]) && is_numeric($parts[1])) ? (int)$parts[1] : 6];
        }
    }
    return [
        'mismatch_score' => settingInt($settings, 'url_mismatch_score', 3),
        'ip_score' => settingInt($settings, 'url_ip_score', 3),
        'shortener_score' => settingInt($settings, 'url_shortener_score', 2),
        'punycode_score' => settingInt($settings, 'url_punycode_score', 3),
        'dbl_enabled' => settingBool($settings, 'url_dbl_enabled', true),
        'dbl_zones' => $zones,
        'max_domains' => max(1, settingInt($settings, 'url_max_domains', 20)),
        'gsb_enabled' => settingBool($settings, 'url_gsb_enabled', false),
        'gsb_api_key' => trim((string)($settings['url_gsb_api_key'] ?? '')),
        'gsb_score' => settingInt($settings, 'url_gsb_score', 10),
        'timeout' => max(1, settingInt($settings, 'url_timeout', 10)),
    ];
}

function extractLinks($html, $text)
{
    $links = [];
    $html = substr((string)$html, 0, 1048576);
    $text = substr((string)$text, 0, 1048576);
    if ($html !== '' && preg_match_all('~<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))[^>]*>(.*?)</a\s*>~is', $html, $m, PREG_SET_ORDER)) {
        foreach ($m as $a) {
            $href = $a[1] !== '' ? $a[1] : ($a[2] !== '' ? $a[2] : ($a[3] ?? ''));
            $href = trim(html_entity_decode($href, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            $label = trim(html_entity_decode(strip_tags($a[4]), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if ($href !== '') {
                $links[] = ['href' => $href, 'text' => $label];
            }
        }
    }
    foreach ([$text, $html] as $blob) {
        if ($blob !== '' && preg_match_all('~\bhttps?://[^\s<>"\'()\[\]{}]+~i', $blob, $m)) {
            foreach ($m[0] as $u) {
                $links[] = ['href' => rtrim(html_entity_decode($u, ENT_QUOTES | ENT_HTML5, 'UTF-8'), '.,;:!?'), 'text' => null];
            }
        }
    }
    return $links;
}

function urlHost($url)
{
    $url = trim((string)$url);
    if (!preg_match('~^https?://~i', $url)) {
        return '';
    }
    $host = parse_url($url, PHP_URL_HOST);
    return $host ? domNormalize($host) : '';
}

function domainInLinkText($text)
{
    $text = trim($text);
    if (strlen($text) > 200 || preg_match('/\s/', $text)) {
        return '';
    }
    if (preg_match('~^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:/?#].*)?$~i', $text, $m)) {
        return domNormalize($m[1]);
    }
    return '';
}

/**
 * URI block list lookup, cached in dnsbl_cache (ip column holds the domain)
 * for an hour, plus an in-run cache.
 */
function dblListed($db, $domain, $zone, array &$runCache)
{
    $key = $domain . '|' . $zone;
    if (array_key_exists($key, $runCache)) {
        return $runCache[$key];
    }
    $stmt = $db->prepare('SELECT listed, checked_at FROM dnsbl_cache WHERE ip = :ip AND zone = :zone');
    $stmt->bindValue(':ip', $domain);
    $stmt->bindValue(':zone', $zone);
    $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
    if ($row && (time() - strtotime($row['checked_at'])) < 3600) {
        return $runCache[$key] = (bool)$row['listed'];
    }

    $fqdn = $domain . '.' . $zone;
    $ips = [];
    if (function_exists('dns_get_record')) {
        $records = @dns_get_record($fqdn, DNS_A);
        $ips = is_array($records) ? array_filter(array_column($records, 'ip')) : [];
    } else {
        $ip = @gethostbyname($fqdn);
        $ips = ($ip && $ip !== $fqdn) ? [$ip] : [];
    }
    $listed = false;
    foreach ($ips as $ip) {
        // 127.0.0.1 = query refused, 127.255.255.x = error code: not "listed"
        if (strpos($ip, '127.') === 0 && $ip !== '127.0.0.1' && strpos($ip, '127.255.255.') !== 0) {
            $listed = true;
            break;
        }
    }

    $upsert = $db->prepare('INSERT OR REPLACE INTO dnsbl_cache (ip, zone, listed, checked_at) VALUES (:ip, :zone, :listed, :t)');
    $upsert->bindValue(':ip', $domain);
    $upsert->bindValue(':zone', $zone);
    $upsert->bindValue(':listed', $listed ? 1 : 0);
    $upsert->bindValue(':t', date('c'));
    $upsert->execute();

    return $runCache[$key] = $listed;
}

function safeBrowsingLookup(array $urls, $apiKey, $timeout)
{
    if (!$urls || !function_exists('curl_init')) {
        return [];
    }
    $payload = [
        'client' => ['clientId' => 'pancernapanda-antispam', 'clientVersion' => '1.0'],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => array_map(function ($u) { return ['url' => $u]; }, array_values($urls)),
        ],
    ];
    $ch = curl_init('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . rawurlencode($apiKey));
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_TIMEOUT => $timeout,
    ]);
    $body = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($body === false || $status !== 200) {
        return [];
    }
    $data = json_decode($body, true);
    $out = [];
    foreach ((array)($data['matches'] ?? []) as $match) {
        if (!empty($match['threat']['url'])) {
            $out[] = $match['threat']['url'];
        }
    }
    return $out;
}

function analyzeUrls($html, $text, array $config, $db, array &$dblCache)
{
    static $shorteners = [
        'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'rb.gy', 't.ly',
        'tiny.cc', 's.id', 'v.gd', 'bl.ink', 'short.io', 'shorte.st', 'adf.ly',
        'qrco.de', 'tiny.one', 'urlz.fr', 'x.co',
    ];
    $score = 0;
    $reasons = [];
    $fired = [];
    $domains = [];
    $urls = [];
    $add = function ($key, $rule, $points, array $extra = []) use (&$score, &$reasons, &$fired) {
        if (isset($fired[$key]) || (int)$points <= 0) {
            return;
        }
        $fired[$key] = true;
        $score += (int)$points;
        $reasons[] = array_merge(['rule' => $rule, 'score' => (int)$points], $extra);
    };

    foreach (extractLinks($html, $text) as $link) {
        $host = urlHost($link['href']);
        if ($host === '') {
            continue;
        }
        $urls[$link['href']] = true;
        if (domIsIp($host)) {
            $add('ip', 'url_ip_host:' . $host, $config['ip_score']);
            continue;
        }
        $reg = domRegistrable($host);
        $domains[$reg] = true;
        if (in_array($host, $shorteners, true) || in_array($reg, $shorteners, true)) {
            $add('short', 'url_shortener:' . $reg, $config['shortener_score']);
        }
        if (strpos($host, 'xn--') !== false) {
            $add('puny', 'url_punycode:' . $host, $config['punycode_score'], ['unicode' => domToUnicode($host)]);
        }
        if ($link['text'] !== null && $link['text'] !== '') {
            $shown = domainInLinkText($link['text']);
            if ($shown !== '' && domRegistrable($shown) !== $reg) {
                $add('mismatch', 'url_text_mismatch:' . $shown . '->' . $reg, $config['mismatch_score']);
            }
        }
    }

    $domains = array_slice(array_keys($domains), 0, $config['max_domains']);
    if ($config['dbl_enabled']) {
        foreach ($config['dbl_zones'] as $z) {
            foreach ($domains as $d) {
                if (dblListed($db, $d, $z['zone'], $dblCache)) {
                    $add('dbl:' . $z['zone'], 'url_dbl:' . $z['zone'], $z['score'], ['domain' => $d]);
                    break;
                }
            }
        }
    }
    if ($config['gsb_enabled'] && $config['gsb_api_key'] !== '' && $urls) {
        $flagged = safeBrowsingLookup(array_slice(array_keys($urls), 0, 50), $config['gsb_api_key'], $config['timeout']);
        if ($flagged) {
            $add('gsb', 'url_safebrowsing', $config['gsb_score'], ['url' => substr($flagged[0], 0, 200)]);
        }
    }
    return ['score' => $score, 'reasons' => $reasons];
}

/* ---------------------------------------------------------------------- */
/* Attachment policy (mirror AttachmentPolicyAnalyzer)                    */
/* ---------------------------------------------------------------------- */

function policyConfigFromSettings(array $settings)
{
    $default = 'exe,scr,pif,com,bat,cmd,vbs,vbe,js,jse,wsf,wsh,hta,msi,msp,cpl,jar,ps1,psm1,lnk,iso,img,vhd,vhdx,reg,scf,chm,dll,appx,msix,xll,url,inf,sct,gadget';
    $raw = isset($settings['attachment_blocked_extensions']) ? (string)$settings['attachment_blocked_extensions'] : $default;
    $blocked = [];
    foreach (preg_split('/[\s,;]+/', $raw) as $e) {
        $e = strtolower(trim($e, " \t\r\n.*"));
        if ($e !== '' && preg_match('/^[a-z0-9]{1,16}$/', $e)) {
            $blocked[$e] = true;
        }
    }
    return [
        'blocked_extensions' => array_keys($blocked),
        'blocked_score' => settingInt($settings, 'attachment_blocked_score', 15),
        'double_ext_score' => settingInt($settings, 'attachment_double_ext_score', 8),
        'mismatch_score' => settingInt($settings, 'attachment_mismatch_score', 10),
        'macro_score' => settingInt($settings, 'attachment_macro_score', 6),
        'encrypted_score' => settingInt($settings, 'attachment_encrypted_score', 5),
    ];
}

function normalizeAttachmentName($name)
{
    $name = trim((string)$name, " \t\r\n\"");
    if (preg_match("/^[\\w\\-]+'[\\w\\-]*'(.+)$/", $name, $m)) {
        $name = rawurldecode($m[1]);
    }
    if (strpos($name, '=?') !== false && function_exists('mb_decode_mimeheader')) {
        $name = mb_decode_mimeheader($name);
    }
    $name = str_replace('\\', '/', $name);
    return mb_strtolower(rtrim($name, " .\t"), 'UTF-8');
}

function fileExtension($name)
{
    $base = basename(str_replace('\\', '/', (string)$name));
    $p = strrpos($base, '.');
    if ($p === false || $p === 0) {
        return '';
    }
    return strtolower(trim(substr($base, $p + 1)));
}

function inspectZip($data)
{
    $out = ['names' => [], 'macro' => false, 'encrypted' => false];
    $len = strlen($data);
    $pos = 0;
    $isOoxml = false;
    $encryptedEntries = 0;
    for ($i = 0; $i < 2000; $i++) {
        $pos = strpos($data, "PK\x03\x04", $pos);
        if ($pos === false || $pos + 30 > $len) {
            break;
        }
        $h = unpack('vversion/vflags/vmethod/vtime/vdate/Vcrc/Vcsize/Vusize/vnamelen/vextralen', substr($data, $pos + 4, 26));
        $name = substr($data, $pos + 30, $h['namelen']);
        if ($name !== '') {
            $out['names'][] = $name;
            if ($name === '[Content_Types].xml') {
                $isOoxml = true;
            }
            if (preg_match('~(^|/)vbaProject\.bin$~i', $name)) {
                $out['macro'] = true;
            }
        }
        if ($h['flags'] & 1) {
            $encryptedEntries++;
        }
        $pos += 30 + $h['namelen'] + $h['extralen'];
    }
    $out['encrypted'] = $encryptedEntries > 0 && !$isOoxml;
    return $out;
}

function utf16le($ascii)
{
    return implode("\0", str_split($ascii)) . "\0";
}

function analyzeAttachmentPolicy(array $attachments, array $config)
{
    static $executableExt = ['exe', 'dll', 'scr', 'com', 'sys', 'cpl', 'ocx', 'drv', 'efi', 'pif', 'bin', 'elf', 'so', 'run', 'out', 'appimage'];
    static $decoyExt = [
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'odt',
        'ods', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tif', 'tiff', 'mp3', 'mp4',
        'avi', 'mov', 'zip', 'rar', '7z', 'htm', 'html', 'csv', 'xml', 'eml',
    ];
    $blocked = $config['blocked_extensions'];
    $score = 0;
    $reasons = [];
    $fired = [];
    $add = function ($key, $rule, $points, $filename) use (&$score, &$reasons, &$fired) {
        if (isset($fired[$key]) || (int)$points <= 0) {
            return;
        }
        $fired[$key] = true;
        $score += (int)$points;
        $reasons[] = ['rule' => $rule, 'score' => (int)$points, 'filename' => $filename];
    };

    foreach ($attachments as $att) {
        $rawName = (string)$att['filename'];
        $name = normalizeAttachmentName($rawName);
        $data = substr((string)$att['data'], 0, 26214400);
        $ext = fileExtension($name);

        if ($ext !== '' && in_array($ext, $blocked, true)) {
            $add('blocked', 'attachment_blocked:' . $ext, $config['blocked_score'], $name);
        }

        $bidi = (bool)preg_match('/\x{202A}|\x{202B}|\x{202C}|\x{202D}|\x{202E}|\x{2066}|\x{2067}|\x{2068}|\x{2069}/u', $rawName . $name);
        $double = false;
        if (!$bidi && $ext !== '' && (in_array($ext, $blocked, true) || in_array($ext, $executableExt, true))) {
            $stem = substr(basename($name), 0, -strlen($ext) - 1);
            $inner = fileExtension(rtrim($stem));
            $double = preg_match('/\s{3,}$/', $stem) || ($inner !== '' && in_array($inner, $decoyExt, true));
        }
        if ($bidi) {
            $add('double', 'attachment_bidi_filename', $config['double_ext_score'], $name);
        } elseif ($double) {
            $add('double', 'attachment_double_extension', $config['double_ext_score'], $name);
        }

        $magic = '';
        if (strncmp($data, 'MZ', 2) === 0 && strlen($data) > 64) {
            $off = unpack('V', substr($data, 60, 4))[1];
            if ($off > 0 && $off < strlen($data) - 4 && substr($data, $off, 4) === "PE\0\0") {
                $magic = 'pe';
            }
        } elseif (strncmp($data, "\x7FELF", 4) === 0) {
            $magic = 'elf';
        }
        if ($magic !== '' && !in_array($ext, $executableExt, true)) {
            $add('mismatch', 'attachment_disguised_executable:' . $magic, $config['mismatch_score'], $name);
        }

        if (strncmp($data, "PK\x03\x04", 4) === 0) {
            $zip = inspectZip($data);
            foreach ($zip['names'] as $inner) {
                $innerExt = fileExtension(normalizeAttachmentName($inner));
                if ($innerExt !== '' && in_array($innerExt, $blocked, true)) {
                    $add('archive', 'attachment_archive_blocked:' . $innerExt, $config['blocked_score'], $name . '/' . basename($inner));
                    break;
                }
            }
            if ($zip['macro']) {
                $add('macro', 'attachment_office_macro', $config['macro_score'], $name);
            }
            if ($zip['encrypted']) {
                $add('encrypted', 'attachment_encrypted_archive', $config['encrypted_score'], $name);
            }
        } elseif (strncmp($data, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 8) === 0) {
            if (strpos($data, utf16le('_VBA_PROJECT')) !== false || strpos($data, utf16le('Macros')) !== false) {
                $add('macro', 'attachment_office_macro', $config['macro_score'], $name);
            }
            if (strpos($data, utf16le('EncryptedPackage')) !== false) {
                $add('encrypted', 'attachment_encrypted_office', $config['encrypted_score'], $name);
            }
        } elseif (strncmp($data, '%PDF', 4) === 0) {
            if (preg_match('~/(JavaScript|JS|Launch)\b~', $data, $m)) {
                $add('macro', 'attachment_pdf_active:' . strtolower($m[1]), $config['macro_score'], $name);
            }
        }
    }
    return ['score' => $score, 'reasons' => $reasons];
}

/* ---------------------------------------------------------------------- */
/* Quarantine management (end-user digest)                                */
/* ---------------------------------------------------------------------- */

/**
 * Quarantine item ids are Maildir base names (without the ":2,FLAGS" info
 * suffix). Reject anything that could escape the folder.
 */
function validQuarantineId($id)
{
    return is_string($id) && $id !== '' && strlen($id) <= 255
        && preg_match('/^[A-Za-z0-9._,=\-]+$/', $id) && strpos($id, '..') === false;
}

function findQuarantineFile($maildirPath, $id)
{
    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/.QUARANTINE/' . $subdir;
        if (!is_dir($dir)) {
            continue;
        }
        foreach (scandir($dir) as $file) {
            if ($file === $id || strpos($file, $id . ':') === 0) {
                return ['path' => $dir . '/' . $file, 'file' => $file, 'subdir' => $subdir];
            }
        }
    }
    return null;
}

function decodeHeaderValue($value)
{
    $value = trim((string)$value);
    if (strpos($value, '=?') !== false && function_exists('mb_decode_mimeheader')) {
        $value = mb_decode_mimeheader($value);
    }
    return $value;
}

function quarantineList($maildirPath, $dbPath, array $options)
{
    $since = isset($options['since']) ? (int)$options['since'] : 0;
    $limit = isset($options['limit']) ? max(1, (int)$options['limit']) : 200;
    $db = getDb($dbPath);
    $scoreStmt = $db->prepare('SELECT score, reasons FROM score_log WHERE file = :f ORDER BY id DESC LIMIT 1');

    $items = [];
    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/.QUARANTINE/' . $subdir;
        if (!is_dir($dir)) {
            continue;
        }
        foreach (scandir($dir) as $file) {
            $path = $dir . '/' . $file;
            if ($file === '.' || $file === '..' || !is_file($path)) {
                continue;
            }
            $headers = readHeaderBlock($path);
            $dateHeader = grabHeaderFolded($headers, 'Date');
            $ts = $dateHeader !== '' ? strtotime($dateHeader) : false;
            $mtime = (int)filemtime($path);
            if ($since > 0 && $mtime < $since) {
                continue; // delivered before the last digest
            }
            $id = preg_replace('/:2,[A-Za-z]*$/', '', $file);
            $from = parseFromHeader(grabHeaderFolded($headers, 'From'));

            $scoreStmt->bindValue(':f', $id);
            $row = $scoreStmt->execute()->fetchArray(SQLITE3_ASSOC);

            $items[] = [
                'id' => $id,
                'from' => $from['email'],
                'from_name' => $from['name'],
                'subject' => mb_substr(decodeHeaderValue(grabHeaderFolded($headers, 'Subject')), 0, 200, 'UTF-8'),
                'date' => $ts ? date('c', $ts) : date('c', $mtime),
                'received_at' => date('c', $mtime),
                'size' => (int)filesize($path),
                'score' => $row ? (int)$row['score'] : null,
                'reasons' => $row ? (json_decode($row['reasons'], true) ?: []) : [],
            ];
        }
    }
    usort($items, function ($a, $b) { return strcmp($b['received_at'], $a['received_at']); });

    return ['success' => true, 'total' => count($items), 'items' => array_slice($items, 0, $limit)];
}

function quarantineRelease($maildirPath, $dbPath, array $options)
{
    $id = $options['id'] ?? '';
    if (!validQuarantineId($id)) {
        return ['success' => false, 'error' => 'Invalid id'];
    }
    $found = findQuarantineFile($maildirPath, $id);
    if (!$found) {
        return ['success' => false, 'error' => 'Message not found in quarantine (already released or deleted?)'];
    }

    $from = parseFromHeader(grabHeaderFolded(readHeaderBlock($found['path']), 'From'));
    $targetDir = $maildirPath . '/' . $found['subdir'];
    if (!is_dir($targetDir)) {
        @mkdir($targetDir, 0755, true);
    }
    if (!@rename($found['path'], $targetDir . '/' . $found['file'])) {
        return ['success' => false, 'error' => 'Could not move message back to INBOX'];
    }

    $db = getDb($dbPath);
    markChecked($db, $id); // never re-quarantine a released message

    $whitelisted = false;
    if (!empty($options['whitelist']) && $from['email'] !== '') {
        $stmt = $db->prepare('SELECT 1 FROM email_whitelist WHERE whitelistemail = :w');
        $stmt->bindValue(':w', $from['email']);
        if (!$stmt->execute()->fetchArray()) {
            $ins = $db->prepare('INSERT INTO email_whitelist (email, whitelistemail, pattern_type) VALUES (:e, :w, :pt)');
            $ins->bindValue(':e', '');
            $ins->bindValue(':w', $from['email']);
            $ins->bindValue(':pt', 'exact');
            $ins->execute();
        }
        $whitelisted = true;
    }

    return ['success' => true, 'id' => $id, 'sender' => $from['email'], 'whitelisted' => $whitelisted];
}

function quarantineDelete($maildirPath, $dbPath, array $options)
{
    $id = $options['id'] ?? '';
    if (!validQuarantineId($id)) {
        return ['success' => false, 'error' => 'Invalid id'];
    }
    $found = findQuarantineFile($maildirPath, $id);
    if (!$found) {
        return ['success' => false, 'error' => 'Message not found in quarantine (already released or deleted?)'];
    }
    $from = parseFromHeader(grabHeaderFolded(readHeaderBlock($found['path']), 'From'));
    if (!@unlink($found['path'])) {
        return ['success' => false, 'error' => 'Could not delete message'];
    }
    return ['success' => true, 'id' => $id, 'sender' => $from['email']];
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

function logDecision($db, $sender, $subject, $score, $decision, $reasons, $file = null)
{
    $stmt = $db->prepare('INSERT INTO score_log (sender, subject, score, decision, reasons, scored_at, file) VALUES (:s, :sub, :sc, :d, :r, :t, :f)');
    $stmt->bindValue(':f', $file);
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
    $db->exec('CREATE TABLE IF NOT EXISTS score_log (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, subject TEXT, score INTEGER, decision TEXT, reasons TEXT, scored_at TEXT, file TEXT)');
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
        // score_log.file links a decision to its Maildir file (quarantine digest).
        $cols = [];
        $res = $db->query('PRAGMA table_info(score_log)');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) { $cols[] = $row['name']; }
        if (!in_array('file', $cols, true)) {
            @$db->exec('ALTER TABLE score_log ADD COLUMN file TEXT');
        }
    }
    $db->exec('CREATE INDEX IF NOT EXISTS idx_score_log_file ON score_log (file)');

    return $db;
}
