<?php

namespace AntispamBundle\Tests\Services\Bayes;

use AntispamBundle\Services\Bayes\BayesMath;
use PHPUnit\Framework\TestCase;

class BayesMathTest extends TestCase
{
    public function testChi2QKnownValues()
    {
        // v = 2: Q = e^(-x/2); v = 4: Q = e^(-x/2) (1 + x/2)
        $this->assertEqualsWithDelta(exp(-1), BayesMath::chi2Q(2.0, 2), 1e-12);
        $this->assertEqualsWithDelta(exp(-3) * 4, BayesMath::chi2Q(6.0, 4), 1e-12);
        // table value: chi2 = 18.307, 10 df -> p = 0.05
        $this->assertEqualsWithDelta(0.05, BayesMath::chi2Q(18.307, 10), 1e-4);
        $this->assertSame(1.0, BayesMath::chi2Q(0.0, 6));
    }

    public function testTokenProbRobinson()
    {
        $this->assertSame(0.5, BayesMath::tokenProb(0, 0, 10, 10));
        // seen once in spam only: (0.45 * 0.5 + 1 * 1) / 1.45
        $this->assertEqualsWithDelta(1.225 / 1.45, BayesMath::tokenProb(1, 0, 10, 10), 1e-12);
        // ratios are normalised by corpus size: 10/100 spam vs 1/10 ham = 0.5
        $this->assertEqualsWithDelta(0.5, BayesMath::tokenProb(10, 1, 100, 10), 1e-12);
        $this->assertLessThan(1.0, BayesMath::tokenProb(1000, 0, 1000, 1000));
    }

    public function testCombine()
    {
        $this->assertSame(0.5, BayesMath::combine([]));
        $this->assertSame(0.5, BayesMath::combine(['a' => 0.55, 'b' => 0.45]), 'weak clues are ignored');
        // one clue -> its own probability
        $this->assertEqualsWithDelta(0.99, BayesMath::combine(['a' => 0.99]), 1e-9);
        $this->assertEqualsWithDelta(0.2, BayesMath::combine(['a' => 0.2]), 1e-9);
        // symmetric: complementary clues give complementary results
        $spam = ['a' => 0.97, 'b' => 0.9, 'c' => 0.3];
        $ham = ['a' => 0.03, 'b' => 0.1, 'c' => 0.7];
        $this->assertEqualsWithDelta(1.0, BayesMath::combine($spam) + BayesMath::combine($ham), 1e-9);
        // equal and opposite evidence cancels out
        $this->assertEqualsWithDelta(0.5, BayesMath::combine(['a' => 0.99, 'b' => 0.01]), 1e-9);
        // many strong clues saturate
        $many = [];
        for ($i = 0; $i < 300; $i++) {
            $many['t' . $i] = 0.95;
        }
        $this->assertGreaterThan(0.9999, BayesMath::combine($many));
    }

    public function testScoreMapping()
    {
        $w = ['spam_score' => 5, 'likely_score' => 3, 'ham_score' => 2];
        $this->assertSame(['score' => 5, 'reason' => ['rule' => 'bayes:0.99', 'score' => 5]], BayesMath::scoreFor(0.9999, $w));
        $this->assertSame(3, BayesMath::scoreFor(0.95, $w)['score']);
        $this->assertSame(['score' => 0, 'reason' => null], BayesMath::scoreFor(0.5, $w));
        $this->assertSame(['score' => -2, 'reason' => ['rule' => 'bayes:0.01', 'score' => -2]], BayesMath::scoreFor(0.0001, $w));
        $this->assertSame(0, BayesMath::scoreFor(0.0001, $w, true)['score'], 'never lowers a blacklisted sender');
        $this->assertSame(0, BayesMath::scoreFor(0.95, ['likely_score' => 0] + $w)['score']);
        $this->assertSame('0.89', BayesMath::label(0.899));
        $this->assertSame('0.02', BayesMath::label(0.0101));
    }
}
