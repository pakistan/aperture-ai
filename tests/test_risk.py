"""Tests for the risk classification engine."""

from aperture.models import RiskTier
from aperture.permissions import classify_risk
from aperture.permissions.risk import CRITICAL_PATTERNS, scope_breadth


class TestCriticalOverride:
    """CRITICAL patterns always override the OWASP score."""

    def test_rm_rf_root(self):
        risk = classify_risk("shell", "execute", "rm -rf /")
        assert risk.tier == RiskTier.CRITICAL
        assert risk.score == 1.0
        assert not risk.reversible
        assert "critical_pattern_match" in risk.factors

    def test_drop_database(self):
        risk = classify_risk("database", "execute", "DROP DATABASE production")
        assert risk.tier == RiskTier.CRITICAL
        assert risk.score == 1.0

    def test_sudo_rm_rf(self):
        risk = classify_risk("shell", "execute", "sudo rm -rf /")
        assert risk.tier == RiskTier.CRITICAL

    def test_dd_dev_zero(self):
        risk = classify_risk("shell", "execute", "dd if=/dev/zero of=/dev/sda")
        assert risk.tier == RiskTier.CRITICAL

    def test_non_critical_not_overridden(self):
        risk = classify_risk("shell", "execute", "ls -la")
        assert risk.tier != RiskTier.CRITICAL


class TestOWASPScoring:
    """OWASP likelihood × impact model."""

    def test_high_danger_tool_high_severity(self):
        risk = classify_risk("shell", "execute", "rm -rf ./build/")
        assert risk.tier in (RiskTier.HIGH, RiskTier.CRITICAL)
        assert risk.score > 0.5

    def test_low_danger_read(self):
        risk = classify_risk("filesystem", "read", "src/main.py")
        assert risk.tier == RiskTier.LOW
        assert risk.score < 0.3

    def test_medium_api_post(self):
        risk = classify_risk("api", "post", "users/create")
        assert risk.tier in (RiskTier.LOW, RiskTier.MEDIUM)

    def test_high_shell_delete_broad(self):
        risk = classify_risk("shell", "execute", "find / -name '*.log' -delete")
        assert risk.tier in (RiskTier.MEDIUM, RiskTier.HIGH)


class TestScopeBreadth:
    """scope_breadth() scoring."""

    def test_specific_file(self):
        assert scope_breadth("src/main.py") < 0.3

    def test_wildcard_increases(self):
        assert scope_breadth("src/*.py") > scope_breadth("src/main.py")

    def test_recursive_broad(self):
        assert scope_breadth("find / -R -name '*.py'") > 0.3

    def test_root_path(self):
        assert scope_breadth("/etc/passwd") > scope_breadth("src/main.py")


class TestRiskFactors:
    """Factor collection for human-readable explanations."""

    def test_destructive_factor(self):
        risk = classify_risk("shell", "execute", "rm -rf ./dist/")
        assert "destructive_action" in risk.factors

    def test_broad_scope_factor(self):
        risk = classify_risk("filesystem", "delete", "/home/**")
        assert "broad_scope" in risk.factors

    def test_high_danger_tool_factor(self):
        risk = classify_risk("shell", "execute", "echo hello")
        assert "high_danger_tool" in risk.factors

    def test_reversible_for_reads(self):
        risk = classify_risk("filesystem", "read", "config.yaml")
        assert risk.reversible is True

    def test_irreversible_for_delete(self):
        risk = classify_risk("filesystem", "delete", "important.db")
        assert risk.reversible is False
