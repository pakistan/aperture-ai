"""Tests for the template-based command explainer."""

from aperture.models import RiskAssessment, RiskTier
from aperture.permissions import explain_action


def _low_risk():
    return RiskAssessment(tier=RiskTier.LOW, score=0.1, factors=[], reversible=True)


def _high_risk():
    return RiskAssessment(tier=RiskTier.HIGH, score=0.8, factors=["destructive_action"], reversible=False)


def _critical_risk():
    return RiskAssessment(tier=RiskTier.CRITICAL, score=1.0, factors=["critical_pattern_match"], reversible=False)


class TestTemplateMatching:
    """Template registry lookups."""

    def test_shell_execute(self):
        explanation = explain_action("shell", "execute", "ls -la", _low_risk())
        assert "ls -la" in explanation
        assert "shell command" in explanation.lower() or "Run" in explanation

    def test_filesystem_read(self):
        explanation = explain_action("filesystem", "read", "src/main.py", _low_risk())
        assert "src/main.py" in explanation

    def test_database_query(self):
        explanation = explain_action("database", "query", "users", _low_risk())
        assert "users" in explanation

    def test_unknown_tool_action(self):
        explanation = explain_action("custom_tool", "custom_action", "some_scope", _low_risk())
        assert "some_scope" in explanation
        assert "custom_action" in explanation


class TestAnnotations:
    """Risk annotations appended to explanations."""

    def test_high_risk_annotated(self):
        explanation = explain_action("shell", "execute", "rm -rf ./build/", _high_risk())
        assert "high risk" in explanation.lower() or "irreversible" in explanation.lower()

    def test_destructive_annotated(self):
        explanation = explain_action("shell", "execute", "rm -rf ./dist/", _high_risk())
        assert "destructive" in explanation.lower()

    def test_low_risk_no_annotation(self):
        explanation = explain_action("filesystem", "read", "readme.md", _low_risk())
        assert "risk" not in explanation.lower()
        assert "destructive" not in explanation.lower()

    def test_critical_annotated(self):
        explanation = explain_action("shell", "execute", "rm -rf /", _critical_risk())
        assert "critical risk" in explanation.lower() or "irreversible" in explanation.lower()

    def test_broad_scope_annotated(self):
        risk = RiskAssessment(tier=RiskTier.HIGH, score=0.7, factors=["broad_scope"], reversible=False)
        explanation = explain_action("filesystem", "delete", "/home/**", risk)
        assert "broad scope" in explanation.lower() or "irreversible" in explanation.lower()
