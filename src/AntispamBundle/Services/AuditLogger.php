<?php

namespace AntispamBundle\Services;

use AntispamBundle\Entity\Account;
use AntispamBundle\Entity\AuditLog;
use AntispamBundle\Entity\User;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Writes the audit log ("Dziennik audytu", table antispam_audit_log): who did
 * what and when. Called with one line from the controllers (Controller\AuditTrait),
 * from Security\AuditSecuritySubscriber (login / logout) and from a few
 * commands. See docs/audit.md.
 *
 * - Rows are inserted with plain DBAL, outside the ORM unit of work: logging
 *   never flushes (or is lost with) the caller's pending entity changes.
 * - Writing is best effort: any failure is caught and reported to the
 *   application log, the audited action itself always goes on.
 * - Details are sanitized: keys that look like secrets are dropped, strings
 *   are shortened, the JSON is capped. Never pass secret values anyway.
 */
class AuditLogger
{
    /** Config key: days to keep audit rows (antispam:purge), 0 = forever. */
    const CONFIG_RETENTION = 'audit.retention_days';
    const DEFAULT_RETENTION_DAYS = 365;

    const MAX_DETAILS_JSON = 4000;
    const MAX_STRING = 300;
    /** Detail keys whose values are never stored. */
    const SECRET_KEY_PATTERN = '/pass|secret|token|api_?key|_key$|^key$|hash|credential|raw/i';

    /** action => Polish label (filter dropdown, table). Unknown keys are shown verbatim. */
    const ACTIONS = [
        'auth.login' => 'Logowanie',
        'auth.login_failed' => 'Nieudane logowanie',
        'auth.logout' => 'Wylogowanie',
        'auth.2fa_verified' => '2FA: kod przy logowaniu',
        'auth.2fa_failed' => '2FA: nieudana weryfikacja',
        'auth.2fa_enabled' => '2FA: włączenie',
        'auth.2fa_disabled' => '2FA: wyłączenie',
        'auth.2fa_backup_codes' => '2FA: nowe kody zapasowe',
        'auth.2fa_reset' => '2FA: reset przez administratora',
        'rule.add' => 'Reguła: dodanie',
        'rule.delete' => 'Reguła: usunięcie',
        'rule.import' => 'Reguły: import',
        'rule.make_global' => 'Reguła: zmiana na wszystkie skrzynki',
        'rules.make_global' => 'Reguły: globalne (konsola)',
        'quarantine.release' => 'Kwarantanna: przywrócenie',
        'quarantine.whitelist' => 'Kwarantanna: zawsze akceptuj',
        'quarantine.delete' => 'Kwarantanna: usunięcie',
        'spambox.restore' => 'Folder spamu: przywrócenie',
        'spam.release' => 'SPAM: przywrócenie (użytkownik)',
        'spam.whitelist' => 'SPAM: przywróć i zawsze akceptuj (użytkownik)',
        'plugin.login' => 'Wtyczka: logowanie',
        'plugin.login_failed' => 'Wtyczka: nieudane logowanie',
        'plugin.report' => 'Wtyczka: zgłoszenie spam/nie spam',
        'plugin.phishing' => 'Wtyczka: zgłoszenie phishingu',
        'phishing.update' => 'Phishing: zmiana statusu / notatki',
        'phishing.block' => 'Phishing: blokada',
        'phishing.delete' => 'Phishing: usunięcie',
        'phishing.eml_download' => 'Phishing: pobranie .eml',
        'settings.save' => 'Ustawienia: zapis',
        'settings.digest_send' => 'Raport kwarantanny: wyślij teraz',
        'settings.uncheck_all' => 'Reset flag sprawdzenia',
        'settings.reset_counters' => 'Reset liczników reguł',
        'account.add' => 'Konto: dodanie',
        'account.edit' => 'Konto: edycja',
        'account.delete' => 'Konto: usunięcie',
        'account.deploy' => 'Konto: wdrożenie agenta',
        'account.sync' => 'Konto: synchronizacja reguł',
        'account.rescan_queued' => 'Konto: ponowny skan całej skrzynki - zlecenie',
        'account.rescan' => 'Konto: ponowny skan całej skrzynki - wynik',
        'account.host_key_reset' => 'Konto: reset klucza hosta SSH',
        'account.oauth_connected' => 'Konto: połączenie OAuth (Microsoft 365 / Google)',
        'account.oauth_disconnected' => 'Konto: rozłączenie OAuth',
        'account.oauth_refresh_failed' => 'Konto: odświeżenie tokenu OAuth nieudane',
        'user.add' => 'Użytkownik: dodanie',
        'user.edit' => 'Użytkownik: edycja',
        'user.delete' => 'Użytkownik: usunięcie',
        'user.password_change' => 'Użytkownik: zmiana własnego hasła',
        'dnsbl.add' => 'DNSBL: dodanie',
        'dnsbl.toggle' => 'DNSBL: włączenie / wyłączenie',
        'dnsbl.delete' => 'DNSBL: usunięcie',
        'cert.sync' => 'Lista CERT: synchronizacja',
        'bayes.trained' => 'Bayes: nauka (ręczna / konsola)',
        'bayes.reset' => 'Bayes: wyczyszczenie bazy',
        'job.cancel' => 'Zadanie w tle: anulowanie',
    ];

    public function __construct(
        private Connection $db,
        private EntityManagerInterface $em,
        private RequestStack $requests,
        private TokenStorageInterface $tokens,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * Record one action. The actor (current user / env admin / anonymous, role)
     * and the client IP come from the security token and the main request
     * unless given ($actor + $actorType, e.g. a digest link or a plugin account).
     *
     * @param array<string, mixed> $details short context, no secrets
     */
    public function log(
        string $action,
        ?string $targetType = null,
        int|string|null $targetId = null,
        ?string $label = null,
        ?string $mailbox = null,
        array $details = [],
        ?string $actor = null,
        ?string $actorType = null,
        ?string $role = null,
    ): void {
        try {
            if ($actor === null) {
                [$actor, $actorType, $role] = $this->currentActor();
            }
            $request = $this->requests->getMainRequest();
            $details = self::sanitize($details);
            $json = $details ? json_encode($details, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) : null;
            if ($json !== null && strlen($json) > self::MAX_DETAILS_JSON) {
                $json = json_encode(['truncated' => true, 'keys' => array_slice(array_keys($details), 0, 50)]);
            }

            $this->db->insert(AuditLog::TABLE, [
                'created_at' => (new \DateTime())->format('Y-m-d H:i:s'),
                'actor' => self::cut($actor !== '' ? $actor : '-', 180),
                'actor_type' => self::cut($actorType ?? AuditLog::ACTOR_ANONYMOUS, 20),
                'role' => $role !== null ? self::cut($role, 20) : null,
                // getClientIp() honours framework.trusted_proxies (SYMFONY_TRUSTED_PROXIES).
                'ip' => $request ? self::cut((string)$request->getClientIp(), 45) ?: null : null,
                'action' => self::cut($action, 64),
                'target_type' => $targetType !== null ? self::cut($targetType, 32) : null,
                'target_id' => $targetId !== null && $targetId !== '' ? self::cut((string)$targetId, 64) : null,
                'target_label' => $label !== null && $label !== '' ? self::cut($label, 255) : null,
                'mailbox' => $mailbox !== null && $mailbox !== '' ? self::cut($mailbox, 255) : null,
                'details' => $json,
            ]);
        } catch (\Throwable $e) {
            // The audited action must not fail because of the audit log.
            $this->logger->error('Audit log write failed: {error}', [
                'error' => $e->getMessage(),
                'exception' => $e,
                'audit_action' => $action,
            ]);
        }
    }

    /**
     * A quarantine action (release / always accept / delete) from the panel, the
     * user area, a digest link or the plugin. $key is the quarantine key
     * (imap / imap-<id> / ssh-<id>); the mailbox address is resolved from it
     * unless given.
     *
     * @param array{success?: bool, sender?: string} $result QuarantineService result
     */
    public function quarantine(string $action, string $source, string $key, string $id, array $result, ?string $mailbox = null, ?string $actor = null, ?string $actorType = null): void
    {
        $action = match ($action) {
            'whitelist' => 'quarantine.whitelist',
            'delete' => 'quarantine.delete',
            'release' => 'quarantine.release',
            default => 'quarantine.unknown',
        };
        $this->log(
            $action,
            targetType: 'message',
            targetId: $id,
            label: ($result['sender'] ?? '') !== '' ? (string)$result['sender'] : null,
            mailbox: $mailbox ?? $this->mailboxForKey($key),
            details: ['source' => $source, 'quarantine' => $key, 'ok' => (bool)($result['success'] ?? false)],
            actor: $actor,
            actorType: $actorType,
        );
    }

    /**
     * Which fields a settings form submitted - names only, never values. A
     * secret field counts as changed when it was filled in or cleared.
     *
     * @param string[] $secretFields
     *
     * @return array{fields: string[], secrets_changed?: string[]}
     */
    public static function formFields(array $post, array $secretFields = []): array
    {
        $fields = [];
        $secrets = [];
        foreach ($post as $name => $value) {
            $name = (string)$name;
            $base = preg_replace('/_clear$/', '', $name);
            if (in_array($base, $secretFields, true)) {
                if ((is_scalar($value) && trim((string)$value) !== '') || ($name !== $base && !empty($value))) {
                    $secrets[$base] = true;
                }
                continue;
            }
            $fields[] = $name;
        }
        sort($fields);
        $out = ['fields' => $fields];
        if ($secrets) {
            $out['secrets_changed'] = array_keys($secrets);
        }
        return $out;
    }

    /**
     * Details as stored: secret-looking keys removed, strings shortened,
     * nesting limited to 3 levels.
     */
    public static function sanitize(array $details, int $depth = 0): array
    {
        $out = [];
        foreach ($details as $k => $v) {
            if (is_string($k) && preg_match(self::SECRET_KEY_PATTERN, $k) && $k !== 'secrets_changed') {
                continue;
            }
            if (is_array($v)) {
                $out[$k] = $depth >= 2 ? '[…]' : self::sanitize($v, $depth + 1);
            } elseif (is_string($v)) {
                $out[$k] = self::cut($v, self::MAX_STRING);
            } elseif (is_scalar($v) || $v === null) {
                $out[$k] = $v;
            } elseif ($v instanceof \DateTimeInterface) {
                $out[$k] = $v->format(\DateTimeInterface::ATOM);
            } else {
                $out[$k] = get_debug_type($v);
            }
        }
        return $out;
    }

    /** @return array{0: string, 1: string, 2: ?string} actor, actor type, role (also used for job requesters) */
    public function currentActor(): array
    {
        $user = $this->tokens->getToken()?->getUser();
        if ($user instanceof User) {
            return [(string)$user->getUsername(), AuditLog::ACTOR_USER, (string)$user->getRole()];
        }
        if ($user instanceof UserInterface) {
            // The legacy administrator from ADMIN_USER (InMemoryUser).
            return [$user->getUserIdentifier(), AuditLog::ACTOR_ENV_ADMIN, in_array('ROLE_ADMIN', $user->getRoles(), true) ? 'ROLE_ADMIN' : null];
        }
        if (PHP_SAPI === 'cli' && $this->requests->getMainRequest() === null) {
            return ['cli', AuditLog::ACTOR_CLI, null];
        }
        return ['anonymous', AuditLog::ACTOR_ANONYMOUS, null];
    }

    /** Mailbox address of a quarantine key (imap / imap-<id> / ssh-<id>), null when unknown. */
    public function mailboxForKey(string $key): ?string
    {
        try {
            if ($key === 'imap') {
                $email = $this->db->fetchOne('SELECT value FROM config WHERE name = ?', ['email']);
                return $email !== false ? (string)$email : null;
            }
            if (preg_match('/^(imap|ssh)-(\d+)$/', $key, $m)) {
                $account = $this->em->getRepository(Account::class)->find((int)$m[2]);
                return $account ? (string)$account->getEmail() : null;
            }
        } catch (\Throwable $e) {
        }
        return null;
    }

    private static function cut(string $value, int $max): string
    {
        return mb_strlen($value) > $max ? mb_substr($value, 0, $max - 1) . '…' : $value;
    }
}
