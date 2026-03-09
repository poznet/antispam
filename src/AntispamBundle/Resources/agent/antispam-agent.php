<?php
/**
 * Antispam Maildir Agent - Standalone PHP script
 * Operates directly on Maildir folders, no IMAP required.
 * Requirements: PHP 7.1+, SQLite3 extension
 */

$defaultMaildir = getenv('HOME') . '/Maildir';
$defaultDb = __DIR__ . '/rules.sqlite';

$options = getopt('', ['maildir:', 'db:']);
$maildirPath = $options['maildir'] ?? $defaultMaildir;
$dbPath = $options['db'] ?? $defaultDb;

$command = $argv[1] ?? 'help';

switch ($command) {
    case 'test':
        echo json_encode(runTest($maildirPath), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'import-rules':
        echo json_encode(importRules($dbPath), JSON_PRETTY_PRINT) . "\n";
        break;
    case 'scan':
        echo json_encode(runScan($maildirPath, $dbPath), JSON_PRETTY_PRINT) . "\n";
        break;
    default:
        echo "Antispam Maildir Agent\n";
        echo "Usage:\n";
        echo "  php antispam-agent.php test\n";
        echo "  php antispam-agent.php import-rules < rules.json\n";
        echo "  php antispam-agent.php scan [--maildir=path] [--db=path]\n";
        break;
}

function runTest($maildirPath)
{
    $result = ['success' => true, 'checks' => []];

    $result['checks']['php_version'] = PHP_VERSION;
    $result['checks']['sqlite3'] = extension_loaded('sqlite3') ? 'available' : 'NOT available';
    if (!extension_loaded('sqlite3')) {
        $result['success'] = false;
    }

    $result['checks']['maildir_path'] = $maildirPath;
    $result['checks']['maildir_exists'] = is_dir($maildirPath) ? 'yes' : 'no';
    $result['checks']['maildir_new'] = is_dir($maildirPath . '/new') ? 'yes' : 'no';
    $result['checks']['maildir_cur'] = is_dir($maildirPath . '/cur') ? 'yes' : 'no';
    $result['checks']['maildir_writable'] = is_writable($maildirPath) ? 'yes' : 'no';

    if (!is_dir($maildirPath)) {
        $result['success'] = false;
    }

    $result['checks']['agent_dir_writable'] = is_writable(__DIR__) ? 'yes' : 'no';

    return $result;
}

function importRules($dbPath)
{
    $input = file_get_contents('php://stdin');
    $data = json_decode($input, true);

    if (!$data) {
        return ['success' => false, 'error' => 'Invalid JSON input'];
    }

    $db = getDb($dbPath);

    $db->exec('DELETE FROM whitelist');
    $db->exec('DELETE FROM email_whitelist');
    $db->exec('DELETE FROM blacklist');
    $db->exec('DELETE FROM email_blacklist');

    $counts = ['whitelist' => 0, 'email_whitelist' => 0, 'blacklist' => 0, 'email_blacklist' => 0];

    if (!empty($data['whitelist'])) {
        $stmt = $db->prepare('INSERT INTO whitelist (email, host) VALUES (:email, :host)');
        foreach ($data['whitelist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':host', $row['host']);
            $stmt->execute();
            $counts['whitelist']++;
        }
    }

    if (!empty($data['email_whitelist'])) {
        $stmt = $db->prepare('INSERT INTO email_whitelist (email, whitelistemail) VALUES (:email, :whitelistemail)');
        foreach ($data['email_whitelist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':whitelistemail', $row['whitelistemail']);
            $stmt->execute();
            $counts['email_whitelist']++;
        }
    }

    if (!empty($data['blacklist'])) {
        $stmt = $db->prepare('INSERT INTO blacklist (email, host) VALUES (:email, :host)');
        foreach ($data['blacklist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':host', $row['host']);
            $stmt->execute();
            $counts['blacklist']++;
        }
    }

    if (!empty($data['email_blacklist'])) {
        $stmt = $db->prepare('INSERT INTO email_blacklist (email, blacklistemail) VALUES (:email, :blacklistemail)');
        foreach ($data['email_blacklist'] as $row) {
            $stmt->bindValue(':email', $row['email']);
            $stmt->bindValue(':blacklistemail', $row['blacklistemail']);
            $stmt->execute();
            $counts['email_blacklist']++;
        }
    }

    return ['success' => true, 'imported' => $counts];
}

function runScan($maildirPath, $dbPath)
{
    $db = getDb($dbPath);

    $stats = [
        'total' => 0,
        'checked' => 0,
        'skipped' => 0,
        'whitelisted' => 0,
        'blacklisted' => 0,
        'moved_to_spam' => 0,
    ];

    // Load rules into memory
    $whitelist = loadRules($db, 'SELECT host FROM whitelist');
    $emailWhitelist = loadRules($db, 'SELECT whitelistemail FROM email_whitelist');
    $blacklist = loadRules($db, 'SELECT host FROM blacklist');
    $emailBlacklist = loadRules($db, 'SELECT blacklistemail FROM email_blacklist');

    // Ensure SPAM folder exists
    $spamNew = $maildirPath . '/.SPAM/new';
    $spamCur = $maildirPath . '/.SPAM/cur';
    if (!is_dir($spamNew)) {
        mkdir($spamNew, 0755, true);
    }
    if (!is_dir($spamCur)) {
        mkdir($spamCur, 0755, true);
    }
    // Maildir requires tmp dir too
    $spamTmp = $maildirPath . '/.SPAM/tmp';
    if (!is_dir($spamTmp)) {
        mkdir($spamTmp, 0755, true);
    }

    // Process new and cur directories
    foreach (['new', 'cur'] as $subdir) {
        $dir = $maildirPath . '/' . $subdir;
        if (!is_dir($dir)) continue;

        $files = scandir($dir);
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;

            $filePath = $dir . '/' . $file;
            if (!is_file($filePath)) continue;

            $stats['total']++;

            // Check if already processed
            $messageId = basename($file);
            // Strip Maildir flags from filename for consistent ID
            $baseId = preg_replace('/:2,[A-Z]*$/', '', $messageId);

            $stmt = $db->prepare('SELECT 1 FROM checked WHERE message_id = :id');
            $stmt->bindValue(':id', $baseId);
            $result = $stmt->execute();
            if ($result->fetchArray()) {
                $stats['skipped']++;
                continue;
            }

            $stats['checked']++;

            // Parse headers
            $headers = parseMailHeaders($filePath);
            $senderEmail = $headers['sender_email'] ?? '';
            $senderHost = $headers['sender_host'] ?? '';

            // Check whitelist (domain)
            if ($senderHost && in_array(strtolower($senderHost), $whitelist)) {
                $stats['whitelisted']++;
                markChecked($db, $baseId);
                continue;
            }

            // Check email whitelist
            if ($senderEmail && in_array(strtolower($senderEmail), $emailWhitelist)) {
                $stats['whitelisted']++;
                markChecked($db, $baseId);
                continue;
            }

            // Check blacklist (domain)
            $isSpam = false;
            if ($senderHost && in_array(strtolower($senderHost), $blacklist)) {
                $stats['blacklisted']++;
                $isSpam = true;
            }

            // Check email blacklist
            if (!$isSpam && $senderEmail && in_array(strtolower($senderEmail), $emailBlacklist)) {
                $stats['blacklisted']++;
                $isSpam = true;
            }

            if ($isSpam) {
                // Move to SPAM folder
                $targetDir = $maildirPath . '/.SPAM/' . $subdir;
                $targetPath = $targetDir . '/' . $file;
                if (rename($filePath, $targetPath)) {
                    $stats['moved_to_spam']++;
                }
            }

            markChecked($db, $baseId);
        }
    }

    return $stats;
}

function parseMailHeaders($filePath)
{
    $result = ['sender_email' => '', 'sender_host' => ''];

    $handle = fopen($filePath, 'r');
    if (!$handle) return $result;

    $headerBlock = '';
    while (($line = fgets($handle)) !== false) {
        // Empty line marks end of headers
        if (trim($line) === '') break;
        $headerBlock .= $line;
    }
    fclose($handle);

    // Try From header first, then Sender
    $email = '';
    if (preg_match('/^From:\s*.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/mi', $headerBlock, $matches)) {
        $email = strtolower($matches[1]);
    } elseif (preg_match('/^Sender:\s*.*?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/mi', $headerBlock, $matches)) {
        $email = strtolower($matches[1]);
    }

    if ($email) {
        $result['sender_email'] = $email;
        $parts = explode('@', $email);
        $result['sender_host'] = $parts[1] ?? '';
    }

    return $result;
}

function loadRules($db, $query)
{
    $rules = [];
    $result = $db->query($query);
    while ($row = $result->fetchArray(SQLITE3_NUM)) {
        $rules[] = strtolower($row[0]);
    }
    return $rules;
}

function markChecked($db, $messageId)
{
    $stmt = $db->prepare('INSERT OR IGNORE INTO checked (message_id) VALUES (:id)');
    $stmt->bindValue(':id', $messageId);
    $stmt->execute();
}

function getDb($dbPath)
{
    $isNew = !file_exists($dbPath);
    $db = new \SQLite3($dbPath);
    $db->busyTimeout(5000);

    if ($isNew) {
        $db->exec('CREATE TABLE IF NOT EXISTS whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS email_whitelist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, whitelistemail TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, host TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS email_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, blacklistemail TEXT)');
        $db->exec('CREATE TABLE IF NOT EXISTS checked (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE)');
    }

    return $db;
}
