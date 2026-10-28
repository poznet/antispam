<?php

namespace AntispamBundle\Services\Bayes;

use AntispamBundle\Entity\BayesMessage;
use AntispamBundle\Entity\BayesToken;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;

/**
 * Token / message counts of the Bayes classifier, with plain DBAL: learning
 * one message touches up to 1000 rows, so it is a few batched upserts
 * (MySQL/MariaDB: INSERT ... ON DUPLICATE KEY UPDATE; SQLite in the tests:
 * INSERT ... ON CONFLICT DO UPDATE) instead of 1000 entities. Counts are
 * changed in SQL (`n = n + 1`), so parallel training loses nothing.
 */
class BayesStore
{
    private const BATCH = 400;

    public function __construct(private Connection $db)
    {
    }

    /** @return array{spam:int, ham:int} learned messages of a scope */
    public function totals(int $scope): array
    {
        $row = $this->db->fetchAssociative(
            'SELECT spam_count, ham_count FROM ' . BayesToken::TABLE . ' WHERE scope = ? AND token_hash = ?',
            [$scope, BayesToken::TOTALS_HASH],
        );

        return ['spam' => (int)($row['spam_count'] ?? 0), 'ham' => (int)($row['ham_count'] ?? 0)];
    }

    /**
     * @param string[] $hexes token hashes
     *
     * @return array<string, array{0:int, 1:int}> hex => [spam, ham], known tokens only
     */
    public function counts(int $scope, array $hexes): array
    {
        $out = [];
        foreach (array_chunk(array_values(array_unique($hexes)), self::BATCH) as $chunk) {
            $ints = array_map([BayesTokenizer::class, 'hexToInt'], $chunk);
            $rows = $this->db->fetchAllNumeric(
                'SELECT token_hash, spam_count, ham_count FROM ' . BayesToken::TABLE . ' WHERE scope = ? AND token_hash IN (' . implode(',', array_fill(0, count($ints), '?')) . ')',
                array_merge([$scope], $ints),
            );
            foreach ($rows as [$hash, $spam, $ham]) {
                if ((int)$hash !== BayesToken::TOTALS_HASH) {
                    $out[BayesTokenizer::intToHex($hash)] = [(int)$spam, (int)$ham];
                }
            }
        }
        return $out;
    }

    /**
     * Add (+1) or remove (-1) one message's tokens and the message total.
     *
     * @param string[] $hexes
     */
    public function apply(int $scope, array $hexes, string $verdict, int $delta): void
    {
        $column = $verdict === BayesMessage::SPAM ? 'spam_count' : 'ham_count';
        $ints = array_map([BayesTokenizer::class, 'hexToInt'], array_values(array_unique($hexes)));
        $ints[] = BayesToken::TOTALS_HASH;
        $now = (new \DateTime())->format('Y-m-d H:i:s');

        $this->db->beginTransaction();
        try {
            foreach (array_chunk($ints, self::BATCH) as $chunk) {
                if ($delta > 0) {
                    $this->upsert($scope, $chunk, $column, $now);
                } else {
                    $this->db->executeStatement(
                        'UPDATE ' . BayesToken::TABLE . " SET {$column} = CASE WHEN {$column} > 0 THEN {$column} - 1 ELSE 0 END, updated_at = ?"
                        . ' WHERE scope = ? AND token_hash IN (' . implode(',', array_fill(0, count($chunk), '?')) . ')',
                        array_merge([$now, $scope], $chunk),
                    );
                }
            }
            if ($delta < 0) {
                $this->db->executeStatement('DELETE FROM ' . BayesToken::TABLE . ' WHERE scope = ? AND spam_count = 0 AND ham_count = 0 AND token_hash <> ?', [$scope, BayesToken::TOTALS_HASH]);
            }
            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    private function upsert(int $scope, array $ints, string $column, string $now): void
    {
        $values = [];
        $params = [];
        foreach ($ints as $int) {
            $values[] = '(?, ?, ?, ?, ?)';
            array_push($params, $scope, $int, $column === 'spam_count' ? 1 : 0, $column === 'ham_count' ? 1 : 0, $now);
        }
        $sql = 'INSERT INTO ' . BayesToken::TABLE . ' (scope, token_hash, spam_count, ham_count, updated_at) VALUES ' . implode(', ', $values);
        if ($this->db->getDatabasePlatform() instanceof AbstractMySQLPlatform) {
            $sql .= " ON DUPLICATE KEY UPDATE {$column} = {$column} + 1, updated_at = VALUES(updated_at)";
        } else {
            $sql .= " ON CONFLICT (scope, token_hash) DO UPDATE SET {$column} = " . BayesToken::TABLE . ".{$column} + 1, updated_at = excluded.updated_at";
        }
        $this->db->executeStatement($sql, $params);
    }

    /** Verdict a message was learned with in a scope, or null. */
    public function learnedVerdict(int $scope, string $fingerprint): ?string
    {
        $v = $this->db->fetchOne('SELECT verdict FROM ' . BayesMessage::TABLE . ' WHERE scope = ? AND fingerprint = ?', [$scope, $fingerprint]);
        return $v === false ? null : (string)$v;
    }

    public function rememberMessage(int $scope, string $fingerprint, string $verdict, ?string $source): void
    {
        $now = (new \DateTime())->format('Y-m-d H:i:s');
        $updated = $this->db->executeStatement(
            'UPDATE ' . BayesMessage::TABLE . ' SET verdict = ?, source = ?, learned_at = ? WHERE scope = ? AND fingerprint = ?',
            [$verdict, $source, $now, $scope, $fingerprint],
        );
        if ($updated === 0) {
            $this->db->insert(BayesMessage::TABLE, ['scope' => $scope, 'fingerprint' => $fingerprint, 'verdict' => $verdict, 'source' => $source, 'learned_at' => $now]);
        }
    }

    /** @return array{tokens:int, spam:int, ham:int, scopes:int, messages:int} whole database (all scopes) */
    public function stats(): array
    {
        $t = BayesToken::TABLE;
        $global = $this->totals(BayesToken::GLOBAL_SCOPE);

        return [
            'tokens' => (int)$this->db->fetchOne("SELECT COUNT(*) FROM {$t} WHERE scope = ? AND token_hash <> ?", [BayesToken::GLOBAL_SCOPE, BayesToken::TOTALS_HASH]),
            'tokens_all' => (int)$this->db->fetchOne("SELECT COUNT(*) FROM {$t} WHERE token_hash <> ?", [BayesToken::TOTALS_HASH]),
            'spam' => $global['spam'],
            'ham' => $global['ham'],
            'scopes' => (int)$this->db->fetchOne("SELECT COUNT(*) FROM {$t} WHERE token_hash = ? AND scope <> ?", [BayesToken::TOTALS_HASH, BayesToken::GLOBAL_SCOPE]),
            'messages' => (int)$this->db->fetchOne('SELECT COUNT(*) FROM ' . BayesMessage::TABLE),
        ];
    }

    /**
     * The most frequent tokens of a scope (for the Maildir agent).
     *
     * @return array<int, array{0:string, 1:int, 2:int}> [hex, spam, ham]
     */
    public function topTokens(int $scope, int $limit): array
    {
        $rows = $this->db->fetchAllNumeric(
            'SELECT token_hash, spam_count, ham_count FROM ' . BayesToken::TABLE . ' WHERE scope = ? AND token_hash <> ? ORDER BY spam_count + ham_count DESC, token_hash ASC LIMIT ' . max(0, $limit),
            [$scope, BayesToken::TOTALS_HASH],
            [ParameterType::INTEGER, ParameterType::INTEGER],
        );

        return array_map(static fn($r) => [BayesTokenizer::intToHex($r[0]), (int)$r[1], (int)$r[2]], $rows);
    }

    /** Delete everything (Wyczyść bazę). @return int deleted token rows */
    public function reset(): int
    {
        $n = $this->db->executeStatement('DELETE FROM ' . BayesToken::TABLE);
        $this->db->executeStatement('DELETE FROM ' . BayesMessage::TABLE);
        return $n;
    }

    /**
     * Retention: learned-message fingerprints older than $messageDays, tokens
     * seen in one message only and not touched for $tokenDays (hapaxes - the
     * bulk of the table, nearly worthless as clues), and scopes of deleted
     * accounts.
     *
     * @param int[] $liveScopes account ids that still exist
     *
     * @return array{messages:int, tokens:int, orphans:int}
     */
    public function purge(int $messageDays, int $tokenDays, array $liveScopes): array
    {
        $out = ['messages' => 0, 'tokens' => 0, 'orphans' => 0];
        if ($messageDays > 0) {
            $out['messages'] = $this->db->executeStatement('DELETE FROM ' . BayesMessage::TABLE . ' WHERE learned_at < ?', [(new \DateTime('-' . $messageDays . ' days'))->format('Y-m-d H:i:s')]);
        }
        if ($tokenDays > 0) {
            $out['tokens'] = $this->db->executeStatement(
                'DELETE FROM ' . BayesToken::TABLE . ' WHERE token_hash <> ? AND spam_count + ham_count <= 1 AND updated_at < ?',
                [BayesToken::TOTALS_HASH, (new \DateTime('-' . $tokenDays . ' days'))->format('Y-m-d H:i:s')],
            );
        }
        $keep = array_merge([BayesToken::GLOBAL_SCOPE], array_map('intval', $liveScopes));
        $in = implode(',', array_fill(0, count($keep), '?'));
        $out['orphans'] = $this->db->executeStatement('DELETE FROM ' . BayesToken::TABLE . " WHERE scope NOT IN ({$in})", $keep)
            + $this->db->executeStatement('DELETE FROM ' . BayesMessage::TABLE . " WHERE scope NOT IN ({$in})", $keep);

        return $out;
    }
}
