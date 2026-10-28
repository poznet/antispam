<?php

namespace AntispamBundle\Services\Bayes;

/**
 * The classifier math, pure functions (SpamBayes defaults):
 *
 *   - Robinson's token probability f(w) = (s*x + n*p(w)) / (s + n), with
 *     unknown-word strength s = 0.45 and prior x = 0.5;
 *   - Fisher / Robinson chi-square combining of the strongest clues
 *     (|f - 0.5| >= 0.1, at most 150): S = 1 - chi2Q(-2 sum ln(1-f), 2n),
 *     H = 1 - chi2Q(-2 sum ln f, 2n), p = (S - H + 1) / 2;
 *   - the probability -> score mapping of the pipeline.
 *
 * Mirrored in the Maildir agent (bayesTokenProb(), bayesChi2Q(),
 * bayesCombine(), bayesScoreFor()); AgentParityTest compares the results.
 */
final class BayesMath
{
    public const UNKNOWN_STRENGTH = 0.45;
    public const UNKNOWN_PROB = 0.5;
    public const MIN_STRENGTH = 0.1;
    public const MAX_DISCRIMINATORS = 150;

    public const SPAM_CUTOFF = 0.99;
    public const LIKELY_CUTOFF = 0.90;
    public const HAM_CUTOFF = 0.01;

    public static function tokenProb(int $spam, int $ham, int $nspam, int $nham): float
    {
        $spamRatio = $spam / max(1, $nspam);
        $hamRatio = $ham / max(1, $nham);
        $p = ($spamRatio + $hamRatio) > 0 ? $spamRatio / ($spamRatio + $hamRatio) : self::UNKNOWN_PROB;
        $n = $spam + $ham;

        return (self::UNKNOWN_STRENGTH * self::UNKNOWN_PROB + $n * $p) / (self::UNKNOWN_STRENGTH + $n);
    }

    /** Survival function of the chi-square distribution with $v (even) degrees of freedom. */
    public static function chi2Q(float $x2, int $v): float
    {
        $m = $x2 / 2.0;
        $sum = $term = exp(-$m);
        for ($i = 1; $i < intdiv($v, 2); $i++) {
            $term *= $m / $i;
            $sum += $term;
        }
        return min($sum, 1.0);
    }

    /**
     * @param array<string, float> $probs token hash => f(w)
     *
     * @return float spam probability 0..1 (0.5 = no opinion)
     */
    public static function combine(array $probs): float
    {
        $clues = [];
        foreach ($probs as $key => $f) {
            $strength = abs($f - 0.5);
            if ($strength >= self::MIN_STRENGTH) {
                $clues[] = [$strength, (string)$key, $f];
            }
        }
        if (!$clues) {
            return 0.5;
        }
        usort($clues, static function ($a, $b) {
            return $b[0] <=> $a[0] ?: strcmp($a[1], $b[1]);
        });
        $clues = array_slice($clues, 0, self::MAX_DISCRIMINATORS);

        $s = 0.0;
        $h = 0.0;
        foreach ($clues as $c) {
            $s += log(1.0 - $c[2]);
            $h += log($c[2]);
        }
        $n = count($clues);
        $s = 1.0 - self::chi2Q(-2.0 * $s, 2 * $n);
        $h = 1.0 - self::chi2Q(-2.0 * $h, 2 * $n);

        return ($s - $h + 1.0) / 2.0;
    }

    /**
     * @param array{spam_score:int, likely_score:int, ham_score:int} $weights ham_score is subtracted
     * @param bool $blacklisted a blacklist rule matched: never lower the score
     *
     * @return array{score:int, reason:?array{rule:string, score:int}}
     */
    public static function scoreFor(float $p, array $weights, bool $blacklisted = false): array
    {
        $score = 0;
        if ($p >= self::SPAM_CUTOFF) {
            $score = (int)$weights['spam_score'];
        } elseif ($p >= self::LIKELY_CUTOFF) {
            $score = (int)$weights['likely_score'];
        } elseif ($p <= self::HAM_CUTOFF && !$blacklisted) {
            $score = -(int)$weights['ham_score'];
        }
        if ($score === 0) {
            return ['score' => 0, 'reason' => null];
        }

        return ['score' => $score, 'reason' => ['rule' => 'bayes:' . self::label($p), 'score' => $score]];
    }

    /** Probability as shown in the reason: two decimals, rounded towards 0.5 (0.995 -> "0.99"). */
    public static function label(float $p): string
    {
        $v = $p >= 0.5 ? floor($p * 100) / 100 : ceil($p * 100) / 100;
        return number_format($v, 2, '.', '');
    }
}
