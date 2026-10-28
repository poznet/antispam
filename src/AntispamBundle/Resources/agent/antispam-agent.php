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
 * `apply-blacklist` re-checks recent INBOX mail (already scanned or not)
 * against the blacklists only, so a newly added rule also clears messages
 * that arrived before it. Only headers are read, which keeps it cheap.
 *
 * It also manages the quarantine for the end-user digest: list, release (with
 * optional sender whitelisting) and delete quarantined messages.
 *
 * Requirements: PHP 7.1+, SQLite3 and mbstring extensions, DNS resolution for
 * DNSBL lookups. Optional: a reachable clamd for ClamAV scanning, the curl
 * extension for VirusTotal / Safe Browsing lookups and the CERT list. All of
 * them are off unless enabled in the synced settings.
 *
 * Output protocol: every command prints exactly one JSON document on STDOUT.
 * PHP warnings never reach STDOUT; they are collected into "warnings".
 */

const AGENT_VERSION = '3.0';
const CERT_DEFAULT_URL = 'https://hole.cert.pl/domains/v2/domains.txt';
const CERT_MAX_BYTES = 52428800;
const CERT_MIN_ROWS = 100;
const CERT_REFRESH_SECONDS = 86400;
const CERT_RETRY_SECONDS = 3600;
const AGENT_DEFAULT_SPAM_THRESHOLD = 10;
const AGENT_DEFAULT_QUARANTINE_THRESHOLD = 5;
const AGENT_COMMIT_EVERY = 50;

// Test suites include this file to check it against the web application's
// analyzers; top-level functions stay defined after this early return.
if (defined('ANTISPAM_AGENT_LIBRARY')) {
    return;
}

// Keep STDOUT a clean JSON channel: warnings are collected, not printed.
ini_set('display_errors', '0');
ini_set('log_errors', '0');
$GLOBALS['agentWarnings'] = [];
set_error_handler(function ($no, $str, $file, $line) {
    if (!(error_reporting() & $no)) {
        return false; // silenced with @: standard handler keeps error_get_last(), prints nothing
    }
    if (count($GLOBALS['agentWarnings']) < 50) {
        $GLOBALS['agentWarnings'][] = $str . ' (line ' . $line . ')';
    }
    return true;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true) && empty($GLOBALS['agentPrinted'])) {
        agentPrint(['success' => false, 'error' => 'Fatal error: ' . $e['message'] . ' (line ' . $e['line'] . ')']);
    }
});

$defaultMaildir = getenv('HOME') . '/Maildir';

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
$dbPath = isset($options['db']) ? agentPath($options['db'], 'db') : agentDefaultDb(__DIR__, $options['account'] ?? null);

try {
    switch ($command) {
        case 'test':
            agentPrint(runTest($maildirPath));
            break;
        case 'import-rules':
            agentPrint(importRules($dbPath, file_get_contents('php://stdin')));
            break;
        case 'scan':
            agentPrint(agentLocked($dbPath, function () use ($maildirPath, $dbPath, $options) {
                return runScan($maildirPath, $dbPath, $options);
            }));
            break;
        case 'apply-blacklist':
            agentPrint(agentLocked($dbPath, function () use ($maildirPath, $dbPath, $options) {
                return applyBlacklist($maildirPath, $dbPath, $options);
            }));
            break;
        case 'health':
            agentPrint(runHealth($maildirPath, $dbPath));
            break;
        case 'quarantine-list':
            agentPrint(quarantineList($maildirPath, $dbPath, $options));
            break;
        case 'quarantine-release':
            agentPrint(quarantineRelease($maildirPath, $dbPath, $options));
            break;
        case 'quarantine-delete':
            agentPrint(quarantineDelete($maildirPath, $dbPath, $options));
            break;
        case 'version':
            agentPrint(['success' => true, 'php' => PHP_VERSION]);
            break;
        default:
            $GLOBALS['agentPrinted'] = true;
            echo "Antispam Maildir Agent " . AGENT_VERSION . "\n";
            echo "Usage:\n";
            echo "  php antispam-agent.php test [--maildir=path]\n";
            echo "  php antispam-agent.php version\n";
            echo "  php antispam-agent.php import-rules [--account=ID] [--db=path] < rules.json\n";
            echo "  php antispam-agent.php scan [--maildir=path] [--account=ID] [--db=path] [--spam-threshold=N] [--quarantine-threshold=N] [--no-dnsbl] [--no-headers] [--no-impersonation] [--no-urls] [--no-cert] [--no-attachment-policy] [--no-clamav] [--no-virustotal]\n";
            echo "  php antispam-agent.php apply-blacklist [--maildir=path] [--account=ID] [--db=path] [--spam-threshold=N] [--days=30] [--limit=5000]\n";
            echo "  php antispam-agent.php health [--maildir=path] [--account=ID] [--db=path]\n";
            echo "  php antispam-agent.php quarantine-list [--maildir=path] [--account=ID] [--db=path] [--since=unix-ts] [--limit=N]\n";
            echo "  php antispam-agent.php quarantine-release --id=ID [--whitelist] [--maildir=path] [--account=ID] [--db=path]\n";
            echo "  php antispam-agent.php quarantine-delete --id=ID [--maildir=path] [--account=ID] [--db=path]\n";
            break;
    }
} catch (\Throwable $e) {
    agentPrint(['success' => false, 'error' => get_class($e) . ': ' . $e->getMessage()]);
    exit(1);
}

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
        agentPrint(['success' => false, 'error' => "Invalid --{$label} path"]);
        exit(2);
    }
    return $path;
}

/**
 * rules-<account>.sqlite next to the agent: one database per mailbox, so two
 * accounts on one host share neither rules nor dedup state. Without
 * --account the legacy shared rules.sqlite is used. A new per-account
 * database is seeded from the legacy one, so the "already checked" history
 * survives the upgrade and old mail is not re-scanned.
 */
function agentDefaultDb($dir, $account)
{
    $legacy = $dir . '/rules.sqlite';
    if ($account === null || $account === true || $account === '') {
        return $legacy;
    }
    if (!preg_match('/^[0-9]{1,10}$/', (string)$account)) {
        agentPrint(['success' => false, 'error' => 'Invalid --account value']);
        exit(2);
    }
    $path = $dir . '/rules-' . $account . '.sqlite';
    if (!file_exists($path) && is_file($legacy) && @copy($legacy, $path)) {
        @chmod($path, 0600);
    }
    return $path;
}

/** Prints the single JSON document of this run, with collected warnings. */
function agentPrint($data)
{
    if (is_array($data)) {
        if (!empty($GLOBALS['agentWarnings'])) {
            $data['warnings'] = $GLOBALS['agentWarnings'];
        }
        if (!isset($data['agent_version'])) {
            $data['agent_version'] = AGENT_VERSION;
        }
    }
    $GLOBALS['agentPrinted'] = true;
    echo agentJson($data) . "\n";
}

/**
 * json_encode that never fails on raw 8-bit header bytes: invalid UTF-8 is
 * replaced first (JSON_INVALID_UTF8_SUBSTITUTE needs PHP 7.2).
 */
function agentJson($data)
{
    $json = json_encode(agentScrub($data), JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR);
    if ($json === false) {
        $json = json_encode(['success' => false, 'error' => 'JSON encoding failed: ' . json_last_error_msg()]);
    }
    return $json;
}

function agentScrub($v)
{
    if (is_array($v)) {
        foreach ($v as $k => $item) {
            $v[$k] = agentScrub($item);
        }
        return $v;
    }
    return is_string($v) ? agentUtf8($v) : $v;
}

/** Valid UTF-8 copy of $s (invalid bytes become "?"). */
function agentUtf8($s)
{
    $s = (string)$s;
    if (preg_match('//u', $s)) {
        return $s;
    }
    if (function_exists('mb_convert_encoding')) {
        $prev = mb_substitute_character();
        mb_substitute_character(0x3F);
        $out = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        mb_substitute_character($prev);
        if (is_string($out) && preg_match('//u', $out)) {
            return $out;
        }
    }
    return preg_replace('/[\x80-\xFF]/', '?', $s);
}

/**
 * Runs $fn holding an exclusive lock next to the database, so a cron scan and
 * a scan started from the panel never move the same files at once.
 */
function agentLocked($dbPath, $fn)
{
    $lock = @fopen($dbPath . '.lock', 'c');
    if (!$lock) {
        return $fn(); // unwritable directory: run unlocked rather than not at all
    }
    if (!flock($lock, LOCK_EX | LOCK_NB)) {
        fclose($lock);
        return ['success' => false, 'locked' => true, 'error' => 'Another scan is already running for this mailbox'];
    }
    try {
        return $fn();
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/* ---------------------------------------------------------------------- */
/* Diagnostics                                                            */
/* ---------------------------------------------------------------------- */

function runTest($maildirPath)
{
    $result = ['success' => true, 'checks' => []];
    $result['checks']['php_version'] = PHP_VERSION;
    if (PHP_VERSION_ID < 70100) {
        $result['success'] = false;
        $result['errors'][] = 'PHP 7.1 or newer is required';
    }
    foreach (['sqlite3' => 'SQLite3', 'mbstring' => 'mbstring'] as $ext => $label) {
        $result['checks'][$ext] = extension_loaded($ext) ? 'available' : 'NOT available';
        if (!extension_loaded($ext)) {
            $result['success'] = false;
            $result['errors'][] = 'PHP extension ' . $label . ' is required';
        }
    }
    $result['checks']['dns_get_record'] = function_exists('dns_get_record') ? 'available' : 'missing (DNSBL will use gethostbyname fallback)';
    $result['checks']['curl'] = function_exists('curl_init') ? 'available' : 'missing (VirusTotal, Safe Browsing and CERT list disabled)';

    $result['checks']['maildir_path'] = $maildirPath;
    $result['checks']['maildir_exists'] = is_dir($maildirPath) ? 'yes' : 'no';
    $result['checks']['maildir_new'] = is_dir($maildirPath . '/new') ? 'yes' : 'no';
    $result['checks']['maildir_cur'] = is_dir($maildirPath . '/cur') ? 'yes' : 'no';
    $result['checks']['maildir_writable'] = is_writable($maildirPath) ? 'yes' : 'no';
    if (!is_dir($maildirPath)) {
        $result['success'] = false;
        $result['errors'][] = 'Maildir not found: ' . $maildirPath;
    }
    $result['checks']['agent_dir_writable'] = is_writable(__DIR__) ? 'yes' : 'no';
    if (!is_writable(__DIR__)) {
        $result['success'] = false;
        $result['errors'][] = 'Agent directory is not writable (the rules database lives there)';
    }
    return $result;
}

function runHealth($maildirPath, $dbPath)
{
    $out = [
        'success' => true,
        'agent_version' => AGENT_VERSION,
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

/**
 * Replaces all rules with the pushed set in one transaction: a malformed
 * payload or a failed write leaves the previous rules untouched.
 */
function importRules($dbPath, $input)
{
    $data = json_decode((string)$input, true);
    if (!is_array($data) || !$data) {
        return ['success' => false, 'error' => 'Invalid JSON input (' . json_last_error_msg() . ', ' . strlen((string)$input) . ' bytes)'];
    }
    foreach (['whitelist', 'email_whitelist', 'blacklist', 'email_blacklist', 'dnsbl', 'settings'] as $section) {
        if (isset($data[$section]) && !is_array($data[$section])) {
            return ['success' => false, 'error' => 'Invalid JSON input: "' . $section . '" must be a list'];
        }
    }

    $db = getDb($dbPath);
    $db->enableExceptions(true);
    $db->exec('BEGIN IMMEDIATE');
    try {
        $counts = importRulesInto($db, $data);
        $db->exec('COMMIT');
    } catch (\Throwable $e) {
        @$db->exec('ROLLBACK');
        return ['success' => false, 'error' => 'Import failed, previous rules kept: ' . $e->getMessage()];
    }

    return ['success' => true, 'imported' => $counts, 'db' => basename($dbPath)];
}

function importRulesInto($db, array $data)
{
    $required = ['whitelist' => 'host', 'email_whitelist' => 'whitelistemail', 'blacklist' => 'host', 'email_blacklist' => 'blacklistemail', 'dnsbl' => 'zone'];
    foreach ($required as $section => $key) {
        foreach ((array)($data[$section] ?? []) as $i => $row) {
            if (!is_array($row) || !isset($row[$key]) || !is_scalar($row[$key])) {
                throw new \InvalidArgumentException($section . '[' . $i . '] has no "' . $key . '"');
            }
        }
    }

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
    // The pushed set is complete: settings no longer sent fall back to defaults.
    if (isset($data['settings']) && is_array($data['settings'])) {
        $db->exec('DELETE FROM settings');
        $stmt = $db->prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (:k, :v)');
        foreach ($data['settings'] as $k => $v) {
            if (is_bool($v)) { $v = $v ? '1' : '0'; }
            $stmt->bindValue(':k', (string)$k);
            $stmt->bindValue(':v', (string)$v);
            $stmt->execute();
            $counts['settings']++;
        }
    }

    return $counts;
}

/* ---------------------------------------------------------------------- */
/* Scan pipeline                                                          */
/* ---------------------------------------------------------------------- */

/**
 * Effective scan configuration. Precedence: CLI flag, then the settings
 * synced from the web panel, then the defaults (which match the web side).
 * With scoring switched off (scoring_enabled = 0) only the lists apply and a
 * blacklist hit is spam, like the web pipeline.
 */
function scanConfig(array $settings, array $options)
{
    $scoring = settingBool($settings, 'scoring_enabled', true);
    $on = function ($flag, $key, $default) use ($options, $settings, $scoring) {
        return $scoring && !isset($options[$flag]) && settingBool($settings, $key, $default);
    };
    $spam = isset($options['spam-threshold']) ? (int)$options['spam-threshold']
        : settingInt($settings, 'spam_threshold', AGENT_DEFAULT_SPAM_THRESHOLD);
    $quarantine = isset($options['quarantine-threshold']) ? (int)$options['quarantine-threshold']
        : settingInt($settings, 'quarantine_threshold', AGENT_DEFAULT_QUARANTINE_THRESHOLD);

    return [
        'scoring' => $scoring,
        'spam_threshold' => $spam,
        'quarantine_threshold' => $quarantine,
        'headers' => $on('no-headers', 'header_check_enabled', true),
        'dnsbl' => $on('no-dnsbl', 'dnsbl_enabled', true),
        'impersonation' => $on('no-impersonation', 'impersonation_enabled', true),
        'urls' => $on('no-urls', 'url_enabled', true),
        'cert' => $on('no-cert', 'cert_enabled', false),
        'policy' => $on('no-attachment-policy', 'attachment_policy_enabled', true),
        'clamav' => $on('no-clamav', 'clamav_enabled', false),
        'vt' => $on('no-virustotal', 'vt_enabled', false) && trim((string)($settings['vt_api_key'] ?? '')) !== '',
    ];
}

/** ham / quarantine / spam for a score, like ScoringService::classify(). */
function agentClassify($score, $forcedSpam, array $cfg)
{
    if ($forcedSpam || $score >= $cfg['spam_threshold']) {
        return 'spam';
    }
    if ($score >= $cfg['quarantine_threshold']) {
        return 'quarantine';
    }
    return 'ham';
}

/**
 * Maildir file name without the ":2,FLAGS" info suffix. Cut at the first
 * colon: Dovecot keyword flags are lower-case letters (":2,Sab").
 */
function agentBaseId($file)
{
    $file = basename((string)$file);
    $p = strpos($file, ':');
    return $p === false ? $file : substr($file, 0, $p);
}

/** The id older agents stored (only upper-case flags were stripped). */
function agentLegacyId($file)
{
    return preg_replace('/:2,[A-Z]*$/', '', basename((string)$file));
}

function runScan($maildirPath, $dbPath, $options = [])
{
    $db = getDb($dbPath);
    $settings = loadSettings($db);
    $cfg = scanConfig($settings, $options);

    $certScore = max(1, settingInt($settings, 'cert_score', $cfg['spam_threshold']));
    if ($cfg['cert']) {
        certRefreshIfStale($db, false, certUrlFromSettings($settings)); // daily, keeps the old list on any error
    }

    $protectedDomains = array_values(array_filter(preg_split('/\s+/', strtolower((string)($settings['impersonation_protected_domains'] ?? '')))));
    $vips = parseVips((string)($settings['impersonation_vips'] ?? ''));
    $urlConfig = urlConfigFromSettings($settings);
    $policyConfig = policyConfigFromSettings($settings);
    $headerConfig = headerConfigFromSettings($settings, $cfg['quarantine_threshold']);
    $dblCache = [];

    $stats = [
        'success' => true,
        'total' => 0, 'checked' => 0, 'skipped' => 0,
        'whitelisted' => 0, 'blacklisted' => 0,
        'quarantined' => 0, 'moved_to_spam' => 0,
        'move_failed' => 0,
        'attachments_flagged' => 0,
        'score_total' => 0,
        'spam_threshold' => $cfg['spam_threshold'],
        'quarantine_threshold' => $cfg['quarantine_threshold'],
        'decisions' => [],
        'errors' => [],
    ];

    $lists = loadAllLists($db);
    $dnsblProviders = [];
    if ($cfg['dnsbl']) {
        $res = $db->query('SELECT id, zone, score, cache_ttl FROM dnsbl_providers WHERE enabled = 1');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) { $dnsblProviders[] = $row; }
    }

    ensureFolder($maildirPath . '/.SPAM');
    ensureFolder($maildirPath . '/.QUARANTINE');

    $checkedStmt = $db->prepare('SELECT message_id FROM checked WHERE message_id = :id OR message_id = :legacy');
    $seen = [];
    $complete = true;
    $tx = agentTxBegin($db);

    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/' . $subdir;
        $files = is_dir($dir) ? @scandir($dir) : false;
        if ($files === false) {
            $complete = false;
            continue;
        }

        foreach ($files as $file) {
            if ($file === '.' || $file === '..' || $file[0] === '.') continue;
            $filePath = $dir . '/' . $file;
            if (!is_file($filePath)) continue;

            $stats['total']++;
            $baseId = agentBaseId($file);
            $legacyId = agentLegacyId($file);
            $seen[$baseId] = true;

            $checkedStmt->bindValue(':id', $baseId);
            $checkedStmt->bindValue(':legacy', $legacyId);
            $hit = $checkedStmt->execute()->fetchArray(SQLITE3_NUM);
            if ($hit) {
                if ($hit[0] !== $baseId) {
                    markChecked($db, $baseId); // migrate an id stored by an older agent
                }
                $stats['skipped']++;
                continue;
            }

            $headers = readHeaderBlock($filePath);
            if ($headers === false) {
                continue; // vanished (expunged or moved to cur/) - seen again next run
            }
            $stats['checked']++;

            try {
                $verdict = scoreMessage($filePath, $headers, $cfg, $lists, $dnsblProviders, $db, [
                    'settings' => $settings,
                    'protected_domains' => $protectedDomains,
                    'vips' => $vips,
                    'url' => $urlConfig,
                    'policy' => $policyConfig,
                    'header' => $headerConfig,
                    'cert_score' => $certScore,
                ], $dblCache);
            } catch (\Throwable $e) {
                $stats['errors'][] = $file . ': ' . $e->getMessage();
                continue; // not marked checked: retried next run
            }

            $decision = $verdict['decision'];
            if ($verdict['attachments_flagged']) { $stats['attachments_flagged']++; }

            if ($decision === 'spam' || $decision === 'quarantine') {
                $move = agentMoveMessage($maildirPath, $subdir, $file, $decision === 'spam' ? '.SPAM' : '.QUARANTINE');
                if (!$move['ok']) {
                    // Not marked checked, so the next run retries the move.
                    $stats['move_failed']++;
                    $stats['errors'][] = $file . ': move to ' . $decision . ' failed: ' . $move['error'];
                    $stats['decisions'][] = ['file' => $file, 'decision' => 'move_failed', 'score' => $verdict['score']];
                    continue;
                }
                if ($decision === 'spam') {
                    $stats['blacklisted']++;
                    $stats['moved_to_spam']++;
                } else {
                    $stats['quarantined']++;
                }
            } elseif ($decision === 'whitelisted') {
                $stats['whitelisted']++;
            }

            $stats['score_total'] += $verdict['score'];
            $stats['decisions'][] = ['file' => $file, 'decision' => $decision, 'score' => $verdict['score']];
            logDecision($db, $verdict['sender'], $verdict['subject'], $verdict['score'], $decision, $verdict['reasons'], $baseId);
            markChecked($db, $baseId);
            agentTxTick($db, $tx);
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
    agentTxEnd($db);

    if ($complete) {
        $pruned = agentPrune($db, $seen, max(30, settingInt($settings, 'agent_retention_days', 180)));
        if ($pruned) { $stats['pruned'] = $pruned; }
    }

    // keep response small - don't return per-message decisions when huge
    if (count($stats['decisions']) > 200) {
        $stats['decisions'] = array_slice($stats['decisions'], 0, 200);
        $stats['decisions_truncated'] = true;
    }
    if (count($stats['errors']) > 50) {
        $stats['errors'] = array_slice($stats['errors'], 0, 50);
    }

    return $stats;
}

function loadAllLists($db)
{
    return [
        'whitelist' => loadListRules($db, 'SELECT host, pattern_type FROM whitelist', 'host'),
        'email_whitelist' => loadListRules($db, 'SELECT whitelistemail, pattern_type FROM email_whitelist', 'whitelistemail'),
        'blacklist' => loadListRules($db, 'SELECT host, pattern_type, score FROM blacklist', 'host'),
        'email_blacklist' => loadListRules($db, 'SELECT blacklistemail, pattern_type, score FROM email_blacklist', 'blacklistemail'),
    ];
}

/**
 * Scores one message. Mirrors the web pipeline order: whitelists short-circuit,
 * blacklists, header heuristics, impersonation, DNSBL, links, CERT list,
 * attachment policy, attachment scanning.
 *
 * @return array{decision:string, score:int, reasons:array, sender:string, subject:string, attachments_flagged:bool}
 */
function scoreMessage($filePath, $headers, array $cfg, array $lists, array $dnsblProviders, $db, array $ctx, array &$dblCache)
{
    $parsed = parseHeaders($headers);
    $senderEmail = $parsed['sender_email'];
    $senderHost = $parsed['sender_host'];
    $out = ['decision' => 'ham', 'score' => 0, 'reasons' => [], 'sender' => $senderEmail, 'subject' => $parsed['subject'], 'attachments_flagged' => false];

    // Whitelist short-circuit
    if ($senderHost && ($hit = matchListReturning($lists['whitelist'], $senderHost))) {
        $out['decision'] = 'whitelisted';
        $out['reasons'][] = ['rule' => 'whitelist:' . $hit['pattern'], 'score' => 0];
        return $out;
    }
    if ($senderEmail && ($hit = matchListReturning($lists['email_whitelist'], $senderEmail))) {
        $out['decision'] = 'whitelisted';
        $out['reasons'][] = ['rule' => 'email_whitelist:' . $hit['pattern'], 'score' => 0];
        return $out;
    }

    $score = 0;
    $reasons = [];
    $forceSpam = false;

    // Blacklist domain / email (rule names as in CheckBlacklist / CheckEmailBlacklist)
    if ($senderHost && ($hit = matchListReturning($lists['blacklist'], $senderHost))) {
        $score += (int)$hit['score'];
        $reasons[] = ['rule' => 'blacklist:' . $hit['pattern'] . ' (' . $hit['pattern_type'] . ')', 'score' => (int)$hit['score']];
        $forceSpam = $forceSpam || !$cfg['scoring'];
    }
    if ($senderEmail && ($hit = matchListReturning($lists['email_blacklist'], $senderEmail))) {
        $score += (int)$hit['score'];
        $reasons[] = ['rule' => 'email_blacklist:' . $hit['pattern'] . ' (' . $hit['pattern_type'] . ')', 'score' => (int)$hit['score']];
        $forceSpam = $forceSpam || !$cfg['scoring'];
    }

    $add = function (array $r) use (&$score, &$reasons) {
        $score += $r['score'];
        foreach ($r['reasons'] as $reason) { $reasons[] = $reason; }
    };

    if ($cfg['headers']) {
        $add(analyzeHeaders($headers, $ctx['header']));
    }

    if ($cfg['impersonation']) {
        $from = parseFromHeader(grabHeader($headers, 'From'));
        $add(analyzeImpersonation([
            'from_name' => $from['name'],
            'from_email' => $from['email'],
            'auth_results' => grabHeader($headers, 'Authentication-Results'), // topmost only
        ], $ctx['protected_domains'], $ctx['vips'], $ctx['settings']));
    }

    if ($dnsblProviders && ($ip = extractConnectingIp($headers))) {
        foreach ($dnsblProviders as $prov) {
            if (dnsblLookup($db, $ip, $prov)) {
                $score += (int)$prov['score'];
                $reasons[] = ['rule' => 'dnsbl:' . $prov['zone'], 'score' => (int)$prov['score']];
            }
        }
    }

    // Body + attachments are parsed once, only when a step needs them.
    $parts = ['attachments' => [], 'html' => '', 'text' => ''];
    if ($cfg['urls'] || $cfg['cert'] || $cfg['policy'] || $cfg['clamav'] || $cfg['vt']) {
        $parts = parseMessageParts($filePath);
    }

    if ($cfg['urls'] && ($parts['html'] !== '' || $parts['text'] !== '')) {
        $add(analyzeUrls($parts['html'], $parts['text'], $ctx['url'], $db, $dblCache));
    }

    // CERT Polska list of dangerous domains (sender + links)
    if ($cfg['cert']) {
        $senders = array_merge(
            [$senderHost],
            certHostsFromAddressHeader(grabHeader($headers, 'Reply-To')),
            certHostsFromAddressHeader(grabHeader($headers, 'Return-Path'))
        );
        $add(certAnalyze($db, array_values(array_filter($senders)), certLinkHosts($parts['html'], $parts['text']), $ctx['cert_score']));
    }

    // Attachment policy (no daemon / API needed)
    if ($cfg['policy'] && $parts['attachments']) {
        $pr = analyzeAttachmentPolicy($parts['attachments'], $ctx['policy']);
        $add($pr);
        if ($pr['score'] > 0) { $out['attachments_flagged'] = true; }
    }

    // Attachment scanning (ClamAV malware + VirusTotal reputation): a hit
    // adds the configured score and forces a spam decision.
    if (($cfg['clamav'] || $cfg['vt']) && $parts['attachments']) {
        $hit = scanAttachments($parts['attachments'], $ctx['settings'], $cfg['clamav'], $cfg['vt']);
        if ($hit) {
            $score += (int)$hit['score'];
            $reasons[] = $hit['reason'];
            $forceSpam = true;
            $out['attachments_flagged'] = true;
        }
    }

    $out['score'] = $score;
    $out['reasons'] = $reasons;
    $out['decision'] = agentClassify($score, $forceSpam, $cfg);
    return $out;
}

/**
 * Moves INBOX/<subdir>/<file> into <folder>/<subdir>/. When the file left
 * new/ in the meantime (the IMAP server moved it to cur/ and appended
 * ":2,FLAGS"), the cur/ copy is moved instead.
 *
 * @return array{ok:bool, error:?string}
 */
function agentMoveMessage($maildirPath, $subdir, $file, $folder)
{
    $src = $maildirPath . '/' . $subdir . '/' . $file;
    if (!is_file($src) && $subdir === 'new') {
        $base = agentBaseId($file);
        foreach ((array)@scandir($maildirPath . '/cur') as $cand) {
            if (is_string($cand) && strpos($cand, $base . ':') === 0) {
                $subdir = 'cur';
                $file = $cand;
                $src = $maildirPath . '/cur/' . $cand;
                break;
            }
        }
    }
    if (!is_file($src)) {
        return ['ok' => false, 'error' => 'message no longer in INBOX'];
    }
    $targetDir = $maildirPath . '/' . $folder . '/' . $subdir;
    if (!is_dir($targetDir) && !@mkdir($targetDir, 0700, true) && !is_dir($targetDir)) {
        return ['ok' => false, 'error' => 'cannot create ' . $folder . '/' . $subdir];
    }
    error_clear_last();
    if (!@rename($src, $targetDir . '/' . $file)) {
        $last = error_get_last();
        return ['ok' => false, 'error' => $last ? preg_replace('/^rename\([^)]*\):\s*/', 'rename: ', $last['message']) : 'rename failed'];
    }
    return ['ok' => true, 'error' => null];
}

/* Batched writes: one transaction per AGENT_COMMIT_EVERY messages / 2 s. */
function agentTxBegin($db)
{
    @$db->exec('BEGIN');
    return ['n' => 0, 't' => microtime(true)];
}

function agentTxTick($db, array &$tx)
{
    $tx['n']++;
    if ($tx['n'] >= AGENT_COMMIT_EVERY || microtime(true) - $tx['t'] > 2) {
        @$db->exec('COMMIT');
        $tx = agentTxBegin($db);
    }
}

function agentTxEnd($db)
{
    @$db->exec('COMMIT');
}

/**
 * Daily housekeeping: score_log and dnsbl_cache rows past retention,
 * scan_log beyond the last 1000 runs, and "checked" markers of files that are
 * no longer in INBOX and older than the retention period. Runs only after a
 * scan that could read both INBOX directories.
 */
function agentPrune($db, array $seen, $retentionDays)
{
    $now = time();
    if ((int)agentMeta($db, 'last_prune_ts', 0) > $now - 86400) {
        return null;
    }
    agentSetMeta($db, 'last_prune_ts', $now);
    $cut = $now - 86400 * (int)$retentionDays;
    $out = [];

    $db->exec('BEGIN');
    $db->exec('CREATE TEMP TABLE IF NOT EXISTS seen_ids (id TEXT PRIMARY KEY)');
    $db->exec('DELETE FROM seen_ids');
    $ins = $db->prepare('INSERT OR IGNORE INTO seen_ids (id) VALUES (:id)');
    foreach (array_keys($seen) as $id) {
        $ins->bindValue(':id', (string)$id);
        $ins->execute();
        $ins->reset();
    }
    $db->exec('DELETE FROM checked WHERE (checked_ts IS NULL OR checked_ts < ' . (int)$cut . ') AND message_id NOT IN (SELECT id FROM seen_ids)');
    $out['checked'] = $db->changes();
    $db->exec("DELETE FROM score_log WHERE datetime(scored_at) < datetime(" . (int)$cut . ", 'unixepoch')");
    $out['score_log'] = $db->changes();
    $db->exec("DELETE FROM dnsbl_cache WHERE datetime(checked_at) < datetime(" . (int)($now - 7 * 86400) . ", 'unixepoch')");
    $out['dnsbl_cache'] = $db->changes();
    $db->exec('DELETE FROM scan_log WHERE id <= (SELECT MAX(id) - 1000 FROM scan_log)');
    $out['scan_log'] = $db->changes();
    $db->exec('COMMIT');

    return $out;
}

function agentMeta($db, $key, $default = null)
{
    $stmt = $db->prepare('SELECT value FROM agent_meta WHERE key = :k');
    $stmt->bindValue(':k', $key);
    $row = $stmt->execute()->fetchArray(SQLITE3_NUM);
    return $row ? $row[0] : $default;
}

function agentSetMeta($db, $key, $value)
{
    $stmt = $db->prepare('INSERT OR REPLACE INTO agent_meta (key, value) VALUES (:k, :v)');
    $stmt->bindValue(':k', $key);
    $stmt->bindValue(':v', (string)$value);
    $stmt->execute();
}

/**
 * Moves INBOX messages delivered in the last --days whose sender matches a
 * blacklist rule worth at least the spam threshold to .SPAM (any blacklist
 * hit when scoring is off, like RetroactiveSpamService). Whitelisted senders
 * are left alone, like in the scan.
 */
function applyBlacklist($maildirPath, $dbPath, $options = [])
{
    $since = time() - 86400 * max(1, (int)($options['days'] ?? 30));
    $limit = max(1, (int)($options['limit'] ?? 5000));

    $db = getDb($dbPath);
    $cfg = scanConfig(loadSettings($db), $options);
    $spamThreshold = $cfg['scoring'] ? $cfg['spam_threshold'] : PHP_INT_MIN;
    $lists = loadAllLists($db);

    $stats = ['success' => true, 'examined' => 0, 'moved_to_spam' => 0, 'move_failed' => 0, 'truncated' => false, 'errors' => []];
    ensureFolder($maildirPath . '/.SPAM');
    $tx = agentTxBegin($db);

    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/' . $subdir;
        if (!is_dir($dir)) continue;

        foreach ((array)@scandir($dir) as $file) {
            if (!is_string($file) || $file === '.' || $file === '..' || $file[0] === '.') continue;
            $filePath = $dir . '/' . $file;
            if (!is_file($filePath) || filemtime($filePath) < $since) continue;
            if ($stats['examined']++ >= $limit) {
                $stats['truncated'] = true;
                break 2;
            }

            $headers = readHeaderBlock($filePath);
            if ($headers === false) continue;
            $parsed = parseHeaders($headers);
            $senderEmail = $parsed['sender_email'];
            $senderHost = $parsed['sender_host'];
            if (!$senderEmail) continue;
            if (($senderHost && matchList($lists['whitelist'], $senderHost)) || matchList($lists['email_whitelist'], $senderEmail)) continue;

            $hit = $senderHost ? matchListReturning($lists['blacklist'], $senderHost) : null;
            $rule = $hit ? 'blacklist:' . $hit['pattern'] . ' (' . $hit['pattern_type'] . ')' : null;
            if (!$hit || (int)$hit['score'] < $spamThreshold) {
                $hit = matchListReturning($lists['email_blacklist'], $senderEmail);
                $rule = $hit ? 'email_blacklist:' . $hit['pattern'] . ' (' . $hit['pattern_type'] . ')' : null;
            }
            if (!$hit || (int)$hit['score'] < $spamThreshold) continue;

            $move = agentMoveMessage($maildirPath, $subdir, $file, '.SPAM');
            if (!$move['ok']) {
                $stats['move_failed']++;
                $stats['errors'][] = $file . ': ' . $move['error'];
                continue;
            }
            $baseId = agentBaseId($file);
            $stats['moved_to_spam']++;
            logDecision($db, $senderEmail, $parsed['subject'], (int)$hit['score'], 'spam', [['rule' => 'retroactive ' . $rule, 'score' => (int)$hit['score']]], $baseId);
            markChecked($db, $baseId);
            agentTxTick($db, $tx);
        }
    }
    agentTxEnd($db);
    $stats['errors'] = array_slice($stats['errors'], 0, 50);

    return $stats;
}

/* ---------------------------------------------------------------------- */
/* Pattern matching (mirror AntispamBundle\Services\PatternMatcher)       */
/* ---------------------------------------------------------------------- */

/**
 * The pattern is kept as stored: regex rules must not be lower-cased
 * (\D, \S, \W would change meaning); matching is case-insensitive anyway.
 */
function loadListRules($db, $query, $valueCol)
{
    $rules = [];
    $res = $db->query($query);
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        $rules[] = [
            'pattern' => (string)$row[$valueCol],
            'pattern_type' => ($row['pattern_type'] ?? '') !== '' ? $row['pattern_type'] : 'exact',
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
    foreach ($rules as $r) {
        if (patternMatch($r['pattern'], $value, $r['pattern_type'])) {
            return $r;
        }
    }
    return null;
}

function patternMatch($pattern, $value, $type)
{
    if ($pattern === null || $pattern === '' || $value === null || $value === '') {
        return false;
    }
    $value = strtolower((string)$value);
    $pattern = (string)$pattern;
    switch ($type) {
        case 'regex':
            $regex = '~' . str_replace('~', '\~', $pattern) . '~i';
            return @preg_match($regex, $value) === 1;
        case 'wildcard':
            $regex = '~^' . globToRegex(strtolower($pattern)) . '$~i';
            return @preg_match($regex, $value) === 1;
        case 'exact':
        default:
            return strtolower($pattern) === $value;
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

/**
 * Header block of a message file, unfolded (RFC 5322 continuation lines
 * joined), or false when the file can no longer be opened.
 */
function readHeaderBlock($filePath)
{
    $handle = @fopen($filePath, 'r');
    if (!$handle) return false;
    $block = '';
    while (($line = fgets($handle)) !== false) {
        if (trim($line) === '' || strlen($block) > 262144) break;
        $block .= $line;
    }
    fclose($handle);
    return unfoldHeaders($block);
}

/** Same as readHeaderBlock() for a message held in memory. */
function readHeaderBlockFromString($raw)
{
    $parts = preg_split('/\r?\n[ \t]*\r?\n/', (string)$raw, 2);
    return unfoldHeaders(substr($parts[0], 0, 262144) . "\n");
}

function unfoldHeaders($block)
{
    return preg_replace('/\r?\n[ \t]+/', ' ', (string)$block);
}

/**
 * Sender = the From: address, like the web pipeline (Sender: is ignored, so
 * a Sender: of a whitelisted domain cannot whitelist the message).
 */
function parseHeaders($block)
{
    $block = unfoldHeaders($block);
    $result = ['sender_email' => '', 'sender_host' => '', 'subject' => ''];
    $result['sender_email'] = extractEmail(grabHeader($block, 'From'));
    if ($result['sender_email']) {
        $result['sender_host'] = domainOf($result['sender_email']);
    }
    $result['subject'] = decodeHeaderValue(grabHeader($block, 'Subject'));
    return $result;
}

/** Header scores; keep in sync with HeaderAnalyzer (AgentParityTest). */
function agentHeaderDefaults()
{
    return [
        'spf_fail' => 6,
        'dkim_fail' => 4,
        'dkim_none' => 1,
        'dmarc_fail' => 6,
        'dmarc_none' => 2,
        'from_reply_mismatch' => 3,
        'suspicious_subject' => 3,
        'missing_message_id' => 2,
        'many_received_hops' => 2,
    ];
}

/**
 * Header scores from the synced settings (header_<rule>_score) and the cap of
 * the header sub-score (header_score_cap): by default one point below the
 * quarantine threshold, so header signals alone never quarantine a message.
 */
function headerConfigFromSettings(array $settings, $quarantineThreshold = AGENT_DEFAULT_QUARANTINE_THRESHOLD)
{
    $cfg = [];
    foreach (agentHeaderDefaults() as $k => $default) {
        $cfg[$k] = settingInt($settings, 'header_' . $k . '_score', $default);
    }
    $cfg['cap'] = settingInt($settings, 'header_score_cap', max(0, (int)$quarantineThreshold - 1));
    return $cfg;
}

/**
 * Only the topmost Authentication-Results / Received-SPF header counts: it is
 * the one added by the receiving server; lower ones can be forged by the
 * sender or be stale results of a forwarding hop.
 */
function analyzeHeaders($block, $config = null)
{
    $config = $config ?: headerConfigFromSettings([]);
    $score = 0;
    $reasons = [];
    $block = unfoldHeaders($block);
    $add = function ($rule) use (&$score, &$reasons, $config) {
        $points = (int)$config[$rule];
        if ($points > 0) {
            $score += $points;
            $reasons[] = ['rule' => $rule, 'score' => $points];
        }
    };

    $auth = strtolower(grabHeader($block, 'Authentication-Results'));
    $spf = strtolower(grabHeader($block, 'Received-SPF'));

    if (preg_match('/\bspf=(fail|softfail)\b/', $auth) || strpos($spf, 'fail') === 0) {
        $add('spf_fail');
    }
    if (preg_match('/\bdkim=fail\b/', $auth)) {
        $add('dkim_fail');
    } elseif (preg_match('/\bdkim=none\b/', $auth)) {
        $add('dkim_none');
    }
    if (preg_match('/\bdmarc=fail\b/', $auth)) {
        $add('dmarc_fail');
    } elseif (preg_match('/\bdmarc=none\b/', $auth)) {
        $add('dmarc_none');
    }

    $from = extractEmail(grabHeader($block, 'From'));
    $reply = extractEmail(grabHeader($block, 'Reply-To'));
    if ($from && $reply && domainOf($from) !== domainOf($reply)) {
        $add('from_reply_mismatch');
    }

    $subject = decodeHeaderValue(grabHeader($block, 'Subject'));
    if ($subject !== '' && isSuspiciousSubject($subject)) {
        $add('suspicious_subject');
    }

    if (!grabHeader($block, 'Message-ID')) {
        $add('missing_message_id');
    }

    if (preg_match_all('/^Received:/mi', $block) > 10) {
        $add('many_received_hops');
    }

    $cap = isset($config['cap']) ? (int)$config['cap'] : null;
    if ($cap !== null && $cap >= 0 && $score > $cap) {
        $reasons[] = ['rule' => 'header_score_cap', 'score' => $cap - $score];
        $score = $cap;
    }

    return ['score' => $score, 'reasons' => $reasons];
}

function isSuspiciousSubject($subject)
{
    $subject = (string)$subject;
    if (strlen($subject) > 8 && mb_strtoupper($subject, 'UTF-8') === $subject) return true;
    if (preg_match('/\${2,}|!{3,}|\?{3,}/', $subject)) return true;
    if (preg_match('/\b(viagra|cialis|lottery|winner|bitcoin|crypto airdrop|nigerian prince)\b/i', $subject)) return true;
    return false;
}

/** First (= topmost) value of a header, unfolded. */
function grabHeader($block, $name)
{
    return grabHeaderFolded($block, $name);
}

/**
 * The addr-spec of an address header: the last <...> group outside quoted
 * strings and comments, so `"ceo@firma.pl" <attacker@evil.com>` yields
 * attacker@evil.com. Without angle brackets the first address-like token.
 */
function extractEmail($line)
{
    $line = (string)$line;
    $bare = preg_replace('/"(?:[^"\\\\]|\\\\.)*"|\((?:[^()\\\\]|\\\\.)*\)/', ' ', $line);
    if (preg_match_all('/<\s*([^<>\s]+@[^<>\s]+?)\s*>/', $bare, $m)) {
        return strtolower(end($m[1]));
    }
    if (preg_match('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', $bare, $m)) {
        return strtolower($m[0]);
    }
    return '';
}

function domainOf($email)
{
    $email = strtolower((string)$email);
    $p = strrpos($email, '@');
    return $p === false ? '' : substr($email, $p + 1);
}

/* ---------------------------------------------------------------------- */
/* DNSBL                                                                  */
/* ---------------------------------------------------------------------- */

/**
 * First public IPv4 address in the Received headers, topmost first, like
 * RawMessageParser::getConnectingIp() (private / reserved hops are skipped).
 */
function extractConnectingIp($headerBlock)
{
    if (preg_match_all('/^Received:(.*)$/mi', unfoldHeaders($headerBlock), $m)) {
        foreach ($m[1] as $line) {
            if (preg_match_all('/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/', $line, $ipm)) {
                foreach ($ipm[1] as $ip) {
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }
    }
    return null;
}

/**
 * Classifies DNSBL answers: "listed" only for 127.0.0.0/8 minus 127.0.0.1
 * (query refused) and 127.255.255.0/24 (Spamhaus error codes, e.g. for
 * public resolvers); no answer is "clean"; anything else (NXDOMAIN hijack by
 * an ISP resolver, error codes only) is "error".
 *
 * @param string[] $ips
 * @return string listed | clean | error
 */
function dnsblClassify(array $ips)
{
    if (!$ips) {
        return 'clean';
    }
    foreach ($ips as $ip) {
        if (strpos($ip, '127.') === 0 && $ip !== '127.0.0.1' && strpos($ip, '127.255.255.') !== 0) {
            return 'listed';
        }
    }
    return 'error';
}

/** A records of $fqdn, [] for NXDOMAIN / no data, null on resolver error. */
function dnsResolveA($fqdn)
{
    if (function_exists('dns_get_record')) {
        $records = @dns_get_record($fqdn, DNS_A);
        if ($records === false) {
            return null;
        }
        return array_values(array_filter(array_column((array)$records, 'ip')));
    }
    $ip = @gethostbyname($fqdn);
    return ($ip && $ip !== $fqdn) ? [$ip] : [];
}

/**
 * @param callable|null $resolver test seam: fn(string $fqdn): ?string[]
 */
function dnsblLookup($db, $ip, $provider, $resolver = null)
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

    $query = implode('.', array_reverse(explode('.', $ip))) . '.' . $zone;
    $ips = $resolver ? $resolver($query) : dnsResolveA($query);
    $class = $ips === null ? 'error' : dnsblClassify($ips);
    if ($class === 'error') {
        return false; // not cached: a resolver problem must not stick for a TTL
    }
    $listed = $class === 'listed';

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
    if (!isset($GLOBALS['agentClamavDown'])) {
        $GLOBALS['agentClamavDown'] = false;
    }

    foreach ($attachments as $att) {
        $data = $att['data'];
        if ($data === '') {
            continue;
        }

        if ($clamavEnabled && !$GLOBALS['agentClamavDown'] && ($clamavMaxSize <= 0 || strlen($data) <= $clamavMaxSize)) {
            $res = clamavScan(
                $data,
                $settings['clamav_dsn'] ?? 'tcp://127.0.0.1:3310',
                (int)($settings['clamav_timeout'] ?? 30)
            );
            // clamd unreachable: skip it for the rest of the run instead of
            // waiting the full timeout again for every attachment.
            if (!empty($res['error']) && strpos($res['error'], 'connect failed') === 0) {
                $GLOBALS['agentClamavDown'] = true;
            }
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
    // [ \t]* (not \s*): an empty header must not swallow the next line.
    if (preg_match('/^' . preg_quote($name, '/') . ':[ \t]*(.*(?:\r?\n[ \t].*)*)/mi', (string)$block, $m)) {
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
    $value = trim(unfoldHeaders($value));
    $email = extractEmail($value);
    $name = '';
    // Display name = text before the last <...> outside quoted strings.
    $masked = preg_replace_callback('/"(?:[^"\\\\]|\\\\.)*"/', function ($m) { return str_repeat('x', strlen($m[0])); }, $value);
    if (($p = strrpos($masked, '<')) !== false) {
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
function dblListed($db, $domain, $zone, array &$runCache, $resolver = null)
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
    $ips = $resolver ? $resolver($fqdn) : dnsResolveA($fqdn);
    $class = $ips === null ? 'error' : dnsblClassify($ips);
    if ($class === 'error') {
        return $runCache[$key] = false; // resolver problem / error code: not cached in the DB
    }
    $listed = $class === 'listed';

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
        // RFC 2047: whitespace between adjacent encoded words is not content.
        $value = mb_decode_mimeheader(preg_replace('/(\?=)\s+(?==\?)/', '$1', $value));
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
    $errors = [];
    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/.QUARANTINE/' . $subdir;
        if (!is_dir($dir)) {
            continue;
        }
        foreach ((array)@scandir($dir) as $file) {
            $path = $dir . '/' . $file;
            if (!is_string($file) || $file === '.' || $file === '..' || !is_file($path)) {
                continue;
            }
            // One unreadable or odd message must not hide the whole list.
            try {
                $mtime = (int)@filemtime($path);
                if ($since > 0 && $mtime < $since) {
                    continue; // delivered before the last digest
                }
                $headers = readHeaderBlock($path);
                if ($headers === false) {
                    continue;
                }
                $dateHeader = grabHeader($headers, 'Date');
                $ts = $dateHeader !== '' ? strtotime($dateHeader) : false;
                $id = agentBaseId($file);
                $from = parseFromHeader(grabHeader($headers, 'From'));

                $scoreStmt->bindValue(':f', $id);
                $row = $scoreStmt->execute()->fetchArray(SQLITE3_ASSOC);

                $items[] = [
                    'id' => $id,
                    'from' => agentUtf8($from['email']),
                    'from_name' => agentUtf8($from['name']),
                    'subject' => mb_substr(agentUtf8(decodeHeaderValue(grabHeader($headers, 'Subject'))), 0, 200, 'UTF-8'),
                    'date' => $ts ? date('c', $ts) : date('c', $mtime),
                    'received_at' => date('c', $mtime),
                    'size' => (int)@filesize($path),
                    'score' => $row ? (int)$row['score'] : null,
                    'reasons' => $row ? (json_decode($row['reasons'], true) ?: []) : [],
                ];
            } catch (\Throwable $e) {
                $errors[] = $file . ': ' . $e->getMessage();
            }
        }
    }
    usort($items, function ($a, $b) { return strcmp($b['received_at'], $a['received_at']); });

    $out = ['success' => true, 'total' => count($items), 'items' => array_slice($items, 0, $limit)];
    if ($errors) {
        $out['errors'] = array_slice($errors, 0, 20);
    }
    return $out;
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
    $stmt = $db->prepare('INSERT OR IGNORE INTO checked (message_id, checked_ts) VALUES (:id, :ts)');
    $stmt->bindValue(':id', $messageId);
    $stmt->bindValue(':ts', time());
    $stmt->execute();
}

function logDecision($db, $sender, $subject, $score, $decision, $reasons, $file = null)
{
    $stmt = $db->prepare('INSERT INTO score_log (sender, subject, score, decision, reasons, scored_at, file) VALUES (:s, :sub, :sc, :d, :r, :t, :f)');
    $stmt->bindValue(':f', $file);
    $stmt->bindValue(':s', mb_substr(agentUtf8($sender), 0, 255, 'UTF-8'));
    $stmt->bindValue(':sub', mb_substr(agentUtf8($subject), 0, 500, 'UTF-8'));
    $stmt->bindValue(':sc', (int)$score);
    $stmt->bindValue(':d', $decision);
    $stmt->bindValue(':r', agentJson($reasons));
    $stmt->bindValue(':t', date('c'));
    $stmt->execute();
}

/** Creates a Maildir++ subfolder (new/cur/tmp + the maildirfolder marker). */
function ensureFolder($path)
{
    foreach (['new', 'cur', 'tmp'] as $sub) {
        $dir = $path . '/' . $sub;
        if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
    }
    if (is_dir($path) && !file_exists($path . '/maildirfolder')) {
        @touch($path . '/maildirfolder');
    }
}

/* ---------------------------------------------------------------------- */
/* CERT Polska "Lista Ostrzezen" (hole.cert.pl) - mirrors CertHoleService  */
/* ---------------------------------------------------------------------- */

function certNormalize($line)
{
    $d = trim((string)$line);
    if ($d === '' || $d[0] === '#') {
        return '';
    }
    $d = preg_replace('~^\*\.~', '', function_exists('mb_strtolower') ? mb_strtolower($d, 'UTF-8') : strtolower($d));
    $d = rtrim($d, '.');
    if (preg_match('/[^\x00-\x7F]/', $d)) {
        if (!function_exists('idn_to_ascii')) {
            return '';
        }
        $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
        $ascii = @idn_to_ascii($d, 0, $variant);
        $d = $ascii ? strtolower($ascii) : '';
    }
    if ($d === '' || strlen($d) > 253 || strpos($d, '.') === false || domIsIp($d)) {
        return '';
    }
    if (!preg_match('/^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/', $d)) {
        return '';
    }
    return $d;
}

function certCandidates($host)
{
    $host = certNormalize($host);
    if ($host === '') {
        return [];
    }
    $labels = explode('.', $host);
    $out = [];
    for ($i = 0, $n = count($labels); $i <= $n - 2; $i++) {
        $out[] = implode('.', array_slice($labels, $i));
    }
    return $out;
}

function certParseList($text)
{
    $set = [];
    foreach (preg_split('/\R/', (string)$text) as $line) {
        if (($d = certNormalize($line)) !== '') {
            $set[$d] = true;
        }
    }
    return array_keys($set);
}

function certSanityError($newCount, $currentCount)
{
    if ($newCount < CERT_MIN_ROWS) {
        return 'list empty or suspiciously short (' . $newCount . ' domains)';
    }
    if ($currentCount > 0 && $newCount < $currentCount * 0.5) {
        return 'list (' . $newCount . ') is less than half of the current one (' . $currentCount . ')';
    }
    return null;
}

function certMeta($db, $key, $default = null)
{
    $stmt = $db->prepare('SELECT value FROM cert_meta WHERE key = :k');
    $stmt->bindValue(':k', $key);
    $row = $stmt->execute()->fetchArray(SQLITE3_NUM);
    return $row ? $row[0] : $default;
}

function certSetMeta($db, $key, $value)
{
    $stmt = $db->prepare('INSERT OR REPLACE INTO cert_meta (key, value) VALUES (:k, :v)');
    $stmt->bindValue(':k', $key);
    $stmt->bindValue(':v', (string)$value);
    $stmt->execute();
}

function certDownload($url, &$error)
{
    if (!function_exists('curl_init')) {
        $error = 'curl extension missing';
        return null;
    }
    $body = '';
    $tooBig = false;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_ENCODING => '',
        CURLOPT_USERAGENT => 'pancernapanda-antispam-agent/1.0',
        CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, &$tooBig) {
            $body .= $chunk;
            if (strlen($body) > CERT_MAX_BYTES) {
                $tooBig = true;
                return 0;
            }
            return strlen($chunk);
        },
    ]);
    $ok = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    if ($tooBig) { $error = 'response too large'; return null; }
    if ($ok === false) { $error = $err; return null; }
    if ($status !== 200) { $error = 'HTTP ' . $status; return null; }
    return $body;
}

/**
 * Refresh the local copy of the CERT list when it is older than a day (failed
 * attempts are retried after an hour). Never throws: on any problem the
 * previous list stays in place.
 */
/** cert_url from the synced settings (HTTPS only), like CertHoleService::getUrl(). */
function certUrlFromSettings(array $settings)
{
    $url = trim((string)($settings['cert_url'] ?? ''));
    return stripos($url, 'https://') === 0 ? $url : CERT_DEFAULT_URL;
}

function certRefreshIfStale($db, $force = false, $url = CERT_DEFAULT_URL)
{
    $now = time();
    $lastOk = (int)certMeta($db, 'last_sync_ts', 0);
    $lastTry = (int)certMeta($db, 'last_attempt_ts', 0);
    if (!$force) {
        if ($lastOk > 0 && $now - $lastOk < CERT_REFRESH_SECONDS) { return null; }
        if ($lastTry > 0 && $lastTry > $lastOk && $now - $lastTry < CERT_RETRY_SECONDS) { return null; }
    }
    certSetMeta($db, 'last_attempt_ts', $now);

    $error = '';
    $body = certDownload($url, $error);
    if ($body === null) {
        certSetMeta($db, 'last_error', $error);
        return false;
    }
    $domains = certParseList($body);
    unset($body);
    $current = (int)$db->querySingle('SELECT COUNT(*) FROM cert_domains');
    if (($err = certSanityError(count($domains), $current)) !== null) {
        certSetMeta($db, 'last_error', $err);
        return false;
    }
    $db->exec('BEGIN');
    $db->exec('DELETE FROM cert_domains');
    $stmt = $db->prepare('INSERT OR IGNORE INTO cert_domains (domain) VALUES (:d)');
    foreach ($domains as $d) {
        $stmt->bindValue(':d', $d);
        $stmt->execute();
        $stmt->reset();
    }
    $db->exec('COMMIT');
    certSetMeta($db, 'last_sync_ts', $now);
    certSetMeta($db, 'last_error', '');
    certSetMeta($db, 'count', count($domains));
    return true;
}

/** @return array ['score' => int, 'reasons' => [...]] */
function certAnalyze($db, array $senderHosts, array $linkHosts, $score)
{
    $hosts = array_merge($senderHosts, array_slice(array_values(array_unique($linkHosts)), 0, 100));
    $stmt = $db->prepare('SELECT 1 FROM cert_domains WHERE domain = :d');
    $seen = [];
    foreach ($hosts as $host) {
        foreach (certCandidates($host) as $c) {
            if (isset($seen[$c])) { continue; }
            $seen[$c] = true;
            $stmt->bindValue(':d', $c);
            $hit = $stmt->execute()->fetchArray();
            $stmt->reset();
            if ($hit) {
                return ['score' => $score, 'reasons' => [['rule' => 'cert_hole:' . $c, 'score' => $score]]];
            }
        }
    }
    return ['score' => 0, 'reasons' => []];
}

function certHostsFromAddressHeader($value)
{
    $hosts = [];
    if (preg_match_all('/@([a-z0-9.\-]+\.[a-z]{2,})/i', (string)$value, $m)) {
        foreach ($m[1] as $h) { $hosts[] = domNormalize($h); }
    }
    return $hosts;
}

function certLinkHosts($html, $text)
{
    $hosts = [];
    foreach (extractLinks($html, $text) as $link) {
        $h = urlHost($link['href']);
        if ($h !== '' && !domIsIp($h)) { $hosts[$h] = true; }
    }
    return array_keys($hosts);
}

function getDb($dbPath)
{
    $isNew = !file_exists($dbPath);
    $umask = umask(0077); // the database holds API keys: owner-only from the start
    try {
        $db = new \SQLite3($dbPath);
    } finally {
        umask($umask);
    }
    if (is_file($dbPath) && (fileperms($dbPath) & 0077)) {
        @chmod($dbPath, 0600); // databases created by agents before 3.0 were 0644
    }
    $db->busyTimeout(10000);

    $db->exec('CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact")');
    $db->exec('CREATE TABLE IF NOT EXISTS email_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, whitelistemail TEXT, pattern_type TEXT DEFAULT "exact")');
    $db->exec('CREATE TABLE IF NOT EXISTS blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10)');
    $db->exec('CREATE TABLE IF NOT EXISTS email_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, blacklistemail TEXT, pattern_type TEXT DEFAULT "exact", score INTEGER DEFAULT 10)');
    $db->exec('CREATE TABLE IF NOT EXISTS checked (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE, checked_ts INTEGER)');
    $db->exec('CREATE TABLE IF NOT EXISTS agent_meta (key TEXT PRIMARY KEY, value TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS dnsbl_providers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, zone TEXT UNIQUE, score INTEGER DEFAULT 5, enabled INTEGER DEFAULT 1, cache_ttl INTEGER DEFAULT 3600)');
    $db->exec('CREATE TABLE IF NOT EXISTS dnsbl_cache (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, zone TEXT, listed INTEGER, checked_at TEXT, UNIQUE(ip, zone))');
    $db->exec('CREATE TABLE IF NOT EXISTS score_log (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, subject TEXT, score INTEGER, decision TEXT, reasons TEXT, scored_at TEXT, file TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS scan_log (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT, total INTEGER, checked INTEGER, moved_to_spam INTEGER, quarantined INTEGER)');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS cert_domains (domain TEXT PRIMARY KEY)');
    $db->exec('CREATE TABLE IF NOT EXISTS cert_meta (key TEXT PRIMARY KEY, value TEXT)');

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
        // checked.checked_ts (agent 3.0) drives pruning; NULL for older rows.
        $cols = [];
        $res = $db->query('PRAGMA table_info(checked)');
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) { $cols[] = $row['name']; }
        if (!in_array('checked_ts', $cols, true)) {
            @$db->exec('ALTER TABLE checked ADD COLUMN checked_ts INTEGER');
        }
    }
    $db->exec('CREATE INDEX IF NOT EXISTS idx_score_log_file ON score_log (file)');

    return $db;
}
