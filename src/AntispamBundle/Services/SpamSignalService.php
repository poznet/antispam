<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\SharedSpamSignal;
use Ddeboer\Imap\MessageInterface;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Builds and stores the privacy-preserving fingerprints used by the shared
 * spam feed, and exposes the feed configuration (feed.* keys in the config table).
 *
 * Two signals are produced per message:
 *   - sender: SHA-256 of the normalized From address
 *   - body:   SHA-256 of the normalized body with the last few lines (the
 *             signature) stripped, so a whole campaign collapses to one hash
 *             even when each copy is personalized.
 *
 * Only hashes ever leave the instance — never raw addresses or message bodies.
 */
class SpamSignalService
{
    const DEFAULT_MATCH_SCORE = 6;
    const DEFAULT_MIN_REPORTS = 1;

    /** Number of trailing lines treated as a signature and dropped before hashing. */
    const SIGNATURE_LINES = 3;

    /** Below this many normalized chars a body is too thin to fingerprint usefully. */
    const MIN_BODY_LENGTH = 24;

    /** Upper bound for a `reports` value taken from a hub. */
    const MAX_IMPORTED_REPORTS = 1000000;

    private $em;
    private $config;

    public function __construct(EntityManagerInterface $em, ?ConfigService $config = null)
    {
        $this->em = $em;
        $this->config = $config;
    }

    // --- configuration -----------------------------------------------------

    public function isEnabled()
    {
        return (bool)$this->readBool('feed.enabled', false);
    }

    public function getMatchScore()
    {
        return max(1, $this->readInt('feed.score', self::DEFAULT_MATCH_SCORE));
    }

    public function getMinReports()
    {
        return max(1, $this->readInt('feed.min_reports', self::DEFAULT_MIN_REPORTS));
    }

    /** Shared secret protecting THIS instance's API. Empty => API disabled. */
    public function getServerKey()
    {
        return trim($this->readString('feed.server_key', ''));
    }

    /** Base URL of the remote hub we push to / pull from. Empty => no client sync. */
    public function getRemoteUrl()
    {
        $url = rtrim(trim($this->readString('feed.remote_url', '')), '/');
        // https only: the X-Feed-Key secret must never travel in plaintext,
        // and other schemes (file://, gopher://...) must not be fetched.
        return stripos($url, 'https://') === 0 ? $url : '';
    }

    /** Secret we present to the remote hub. */
    public function getRemoteKey()
    {
        return trim($this->readString('feed.remote_key', ''));
    }

    public function getLastPushId()
    {
        return $this->readInt('feed.last_push_id', 0);
    }

    public function setLastPushId($id)
    {
        if ($this->config) { $this->config->set('feed.last_push_id', (int)$id); }
    }

    public function getLastPullAt()
    {
        $v = trim($this->readString('feed.last_pull_at', ''));
        if ($v === '') { return null; }
        try { return new \DateTime($v); } catch (\Exception $e) { return null; }
    }

    public function setLastPullAt($iso)
    {
        if ($this->config) { $this->config->set('feed.last_pull_at', (string)$iso); }
    }

    // --- signal extraction -------------------------------------------------

    /**
     * Compute the {type, hash} signals for a message. Returns an empty array on
     * failure; individual signals are skipped when their source is unusable.
     *
     * @return array<int, array{type:string, hash:string}>
     */
    public function signalsForMessage(MessageInterface $message)
    {
        $sender = null;
        try {
            if ($message->getFrom()) { $sender = $message->getFrom()->getAddress(); }
        } catch (\Throwable $e) {}

        $body = null;
        try {
            $body = $message->getBodyText();
            if ($body === null || $body === '') { $body = strip_tags((string)$message->getBodyHtml()); }
        } catch (\Throwable $e) {}

        return $this->signalsFor($sender, $body);
    }

    /**
     * Compute the {type, hash} signals from an already-extracted sender address
     * and plain-text body (used for raw messages submitted by the Thunderbird
     * plugin, which never pass through Ddeboer\Imap).
     *
     * @return array<int, array{type:string, hash:string}>
     */
    public function signalsFor($sender, $body)
    {
        $signals = [];
        if ($hash = $this->hashSender($sender)) {
            $signals[] = ['type' => SharedSpamSignal::TYPE_SENDER, 'hash' => $hash];
        }
        if ($hash = $this->hashBody($body)) {
            $signals[] = ['type' => SharedSpamSignal::TYPE_BODY, 'hash' => $hash];
        }
        return $signals;
    }

    /** Normalize and hash a sender address; null when unusable. */
    public function hashSender($address)
    {
        $norm = $this->normalizeSender($address);
        return $norm === null ? null : hash('sha256', 'sender:' . $norm);
    }

    /** Normalize and hash a message body; null when too thin to be meaningful. */
    public function hashBody($body)
    {
        $norm = $this->normalizeBody($body);
        return $norm === null ? null : hash('sha256', 'body:' . $norm);
    }

    public function normalizeSender($address)
    {
        $address = strtolower(trim((string)$address));
        if ($address === '' || strpos($address, '@') === false) { return null; }
        // Drop plus-addressing (user+tag@domain => user@domain) so tagged
        // variants of the same spammer collapse to one signal.
        list($local, $domain) = explode('@', $address, 2);
        $local = explode('+', $local, 2)[0];
        $domain = trim($domain);
        if ($local === '' || $domain === '') { return null; }
        return $local . '@' . $domain;
    }

    /**
     * Normalize a body for fingerprinting: drop the trailing signature lines,
     * lower-case, strip URLs / e-mails / digits (the parts spammers randomize),
     * and collapse whitespace. Returns null when too little text remains.
     */
    public function normalizeBody($body)
    {
        $body = (string)$body;
        if ($body === '') { return null; }

        // Normalize newlines and split into trimmed, non-empty lines.
        $lines = preg_split('/\r\n|\r|\n/', $body);
        $lines = array_values(array_filter(array_map('trim', $lines), function ($l) {
            return $l !== '';
        }));
        if (!$lines) { return null; }

        // Strip the trailing signature lines.
        if (count($lines) > self::SIGNATURE_LINES) {
            $lines = array_slice($lines, 0, count($lines) - self::SIGNATURE_LINES);
        } else {
            $lines = [];
        }
        if (!$lines) { return null; }

        $text = strtolower(implode(' ', $lines));
        // Remove URLs and e-mail addresses (unique tracking links / recipient).
        $text = preg_replace('#https?://\S+#', ' ', $text);
        $text = preg_replace('#www\.\S+#', ' ', $text);
        $text = preg_replace('#[\w.+-]+@[\w.-]+#', ' ', $text);
        // Drop digits (order numbers, prices, codes) and non-letter noise.
        $text = preg_replace('#[^a-ząćęłńóśźż\s]#u', ' ', $text);
        $text = trim(preg_replace('#\s+#u', ' ', $text));

        if (mb_strlen($text) < self::MIN_BODY_LENGTH) { return null; }
        return $text;
    }

    // --- persistence -------------------------------------------------------

    /**
     * Upsert a batch of {type, hash} signals. New signals are created with the
     * given origin; existing ones get their report count bumped and timestamp
     * refreshed. Caller is responsible for flushing.
     *
     * @return int number of rows touched (created or updated)
     */
    public function record(array $signals, $origin = SharedSpamSignal::ORIGIN_LOCAL, $reportsEach = 1)
    {
        $repo = $this->em->getRepository(SharedSpamSignal::class);
        $touched = 0;

        $valid = [];
        foreach ($signals as $sig) {
            $type = $sig['type'] ?? null;
            $hash = $sig['hash'] ?? null;
            if ($this->isValidType($type) && $this->isValidHash($hash)) {
                $valid[] = ['type' => $type, 'hash' => $hash];
            }
        }
        $existing = $repo->findByTypeHashPairs($valid);

        foreach ($valid as $sig) {
            $type = $sig['type'];
            $hash = $sig['hash'];

            $entity = $existing[$type . ':' . $hash] ?? null;
            if ($entity) {
                $entity->addReport($reportsEach)->touch();
                // A locally-confirmed hit promotes a previously remote-only signal.
                if ($origin === SharedSpamSignal::ORIGIN_LOCAL) {
                    $entity->setOrigin(SharedSpamSignal::ORIGIN_LOCAL);
                }
            } else {
                $entity = new SharedSpamSignal();
                $entity->setType($type)->setHash($hash)
                    ->setOrigin($origin)->setReports(max(1, (int)$reportsEach));
                $this->em->persist($entity);
                $existing[$type . ':' . $hash] = $entity;
            }
            $touched++;
        }

        return $touched;
    }

    /**
     * Import signals pulled from a hub. Unlike record() this does not add one
     * report per pull: the hub's `reports` is already the total it has seen,
     * and that total includes our own pushes. So the local count becomes
     * max(local, hub) - pulling our own pushed signal back (an echo) never
     * raises its count, so a signal can't corroborate itself through the hub
     * (feed.min_reports). Origin is never changed: a local signal stays
     * local. Re-importing the same page is a no-op, so pull cursors may overlap.
     * Caller is responsible for flushing.
     *
     * @param array<int, array{type:string, hash:string, reports?:int}> $signals
     * @return int number of rows created or changed
     */
    public function importRemote(array $signals)
    {
        $valid = [];
        foreach ($signals as $sig) {
            $type = $sig['type'] ?? null;
            $hash = $sig['hash'] ?? null;
            if (!$this->isValidType($type) || !$this->isValidHash($hash)) {
                continue;
            }
            $reports = min(self::MAX_IMPORTED_REPORTS, max(1, (int)($sig['reports'] ?? 1)));
            $k = $type . ':' . $hash;
            $valid[$k] = ['type' => $type, 'hash' => $hash, 'reports' => max($reports, $valid[$k]['reports'] ?? 0)];
        }
        if (!$valid) {
            return 0;
        }
        $existing = $this->em->getRepository(SharedSpamSignal::class)->findByTypeHashPairs(array_values($valid));

        $touched = 0;
        foreach ($valid as $k => $sig) {
            $entity = $existing[$k] ?? null;
            if ($entity) {
                if ($sig['reports'] > $entity->getReports()) {
                    $entity->setReports($sig['reports'])->touch();
                    $touched++;
                }
                continue;
            }
            $entity = new SharedSpamSignal();
            $entity->setType($sig['type'])->setHash($sig['hash'])
                ->setOrigin(SharedSpamSignal::ORIGIN_REMOTE)->setReports($sig['reports']);
            $this->em->persist($entity);
            $touched++;
        }
        return $touched;
    }

    /** Flush pending signal changes to the database. */
    public function flush()
    {
        $this->em->flush();
    }

    /**
     * Does the message match a trusted shared signal? Returns the matching
     * signals (type + reports) so the caller can score and log them.
     *
     * @return array<int, array{type:string, reports:int}>
     */
    public function matchMessage(MessageInterface $message)
    {
        return $this->matchSignals($this->signalsForMessage($message));
    }

    /**
     * @param array<int, array{type:string, hash:string}> $signals
     * @return array<int, array{type:string, reports:int}>
     */
    public function matchSignals(array $signals)
    {
        $hits = [];
        if (!$signals) {
            return $hits;
        }
        $repo = $this->em->getRepository(SharedSpamSignal::class);
        $minReports = $this->getMinReports();
        $entities = $repo->findByTypeHashPairs($signals);
        foreach ($signals as $sig) {
            $entity = $entities[$sig['type'] . ':' . $sig['hash']] ?? null;
            if ($entity && $entity->getReports() >= $minReports) {
                $hits[] = ['type' => $entity->getType(), 'reports' => $entity->getReports()];
            }
        }

        return $hits;
    }

    public function isValidType($type)
    {
        return in_array($type, [SharedSpamSignal::TYPE_SENDER, SharedSpamSignal::TYPE_BODY], true);
    }

    public function isValidHash($hash)
    {
        return is_string($hash) && preg_match('/^[a-f0-9]{64}$/', $hash) === 1;
    }

    // --- config helpers ----------------------------------------------------

    private function readInt($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (int)$v;
    }

    private function readString($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        return ($v === null || $v === '') ? $default : (string)$v;
    }

    private function readBool($key, $default)
    {
        if (!$this->config) return $default;
        $v = $this->config->get($key);
        if ($v === null || $v === '') return $default;
        if (is_bool($v)) return $v;
        return in_array(strtolower((string)$v), ['1', 'true', 'yes', 'on'], true);
    }
}
