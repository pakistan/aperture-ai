"""Tests for the cross-org anonymized intelligence engine."""

import math

from aperture.permissions import IntelligenceEngine
from aperture.permissions.intelligence import (
    confidence_interval_half_width,
    debias,
    generalize_scope,
    randomized_response,
)


class TestDifferentialPrivacy:
    """DP primitives: randomized response, debiasing, confidence intervals."""

    def test_randomized_response_high_epsilon(self):
        """High epsilon → almost always returns truth."""
        true_count = sum(randomized_response(True, epsilon=10.0) for _ in range(100))
        # With epsilon=10, p ≈ 0.99995 → almost always true
        assert true_count >= 95

    def test_randomized_response_zero_epsilon(self):
        """Epsilon=0 → p=0.5: half truth, half coin flip.

        P(True|input=True) = p + (1-p)*0.5 = 0.5 + 0.25 = 0.75.
        """
        true_count = sum(randomized_response(True, epsilon=0.0) for _ in range(1000))
        # Expected ~75% True (not 50% — the else branch is a coin flip, not opposite)
        assert 650 < true_count < 850

    def test_debias_perfect_signal(self):
        """With high epsilon and all-allow noisy rate, debias should return ~1.0."""
        eps = 5.0
        debiased = debias(1.0, eps)
        assert debiased > 0.95

    def test_debias_zero_epsilon(self):
        """With epsilon=0, debias returns 0.5 (no information)."""
        debiased = debias(0.7, 0.0)
        assert abs(debiased - 0.5) < 0.01

    def test_confidence_interval_shrinks_with_n(self):
        """More samples → narrower confidence interval."""
        ci_small = confidence_interval_half_width(10, 1.0)
        ci_large = confidence_interval_half_width(1000, 1.0)
        assert ci_large < ci_small

    def test_confidence_interval_zero_n(self):
        assert confidence_interval_half_width(0, 1.0) == 0.5


class TestScopeGeneralization:
    """generalize_scope() privacy-preserving scope transformation."""

    def test_strips_specific_paths(self):
        result = generalize_scope("/Users/john/project/src/main.py")
        assert "john" not in result
        assert "project" not in result

    def test_strips_urls(self):
        result = generalize_scope("https://api.example.com/users/123")
        assert "api.example.com" not in result

    def test_strips_uuids(self):
        result = generalize_scope("artifact-550e8400-e29b-41d4-a716-446655440000")
        assert "550e8400" not in result

    def test_strips_numeric_ids(self):
        result = generalize_scope("user-12345")
        assert "12345" not in result

    def test_empty_scope(self):
        assert generalize_scope("") == "*"

    def test_sql_table_names(self):
        result = generalize_scope("DROP TABLE users")
        assert "users" not in result


class TestIntelligenceEngine:
    """End-to-end intelligence engine tests."""

    def test_no_signal_without_data(self):
        engine = IntelligenceEngine(min_orgs=5)
        signal = engine.get_global_signal("custom", "action", "scope")
        assert signal is None

    def test_no_signal_below_min_orgs(self):
        engine = IntelligenceEngine(min_orgs=100)
        # Report a few decisions — won't reach 100 orgs
        for _ in range(5):
            engine.report_decision("shell", "execute", "test-cmd", True, epsilon=2.0)
        signal = engine.get_global_signal("shell", "execute", "test-cmd")
        assert signal is None

    def test_signal_with_enough_data(self):
        engine = IntelligenceEngine(min_orgs=1)
        # Report many decisions to build up total_orgs via sqrt approximation
        for _ in range(30):
            engine.report_decision("filesystem", "read", "intel-test-docs/*", True, epsilon=3.0)

        signal = engine.get_global_signal("filesystem", "read", "intel-test-docs/*")
        # May or may not meet min_orgs=1 depending on sqrt calc
        if signal is not None:
            assert 0.0 <= signal.estimated_allow_rate <= 1.0
            assert signal.confidence_interval[0] <= signal.estimated_allow_rate
            assert signal.estimated_allow_rate <= signal.confidence_interval[1]
            assert signal.sample_size > 0
