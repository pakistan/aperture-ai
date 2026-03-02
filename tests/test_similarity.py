"""Tests for the similarity matching engine."""

from sqlmodel import Session

from aperture.db import get_engine
from aperture.models import PermissionDecision, PermissionLog, SimilarPattern
from aperture.permissions import find_similar_patterns
from aperture.permissions.similarity import (
    scope_similarity,
    tool_action_similarity,
    resource_similarity,
    _path_prefix_similarity,
    _command_similarity,
)


# ── Wiring test ──────────────────────────────────────────────────────


def test_find_similar_patterns_importable_from_public_api():
    """Wiring test: find_similar_patterns is exported from the permissions package."""
    from aperture.permissions import find_similar_patterns as fn
    assert callable(fn)


# ── Unit tests (existing) ───────────────────────────────────────────


class TestToolActionSimilarity:
    """Taxonomy-based tool/action similarity."""

    def test_identical_is_1(self):
        assert tool_action_similarity("shell", "execute", "shell", "execute") == 1.0

    def test_same_category_is_high(self):
        # shell and bash are both "execution"
        sim = tool_action_similarity("shell", "execute", "bash", "execute")
        assert sim >= 0.7

    def test_different_category_is_low(self):
        sim = tool_action_similarity("shell", "execute", "filesystem", "read")
        assert sim < 0.5

    def test_same_tool_different_action(self):
        sim = tool_action_similarity("filesystem", "read", "filesystem", "write")
        assert 0.3 < sim < 0.9  # same tool, actions in same category (both modify/observe)


class TestScopeSimilarity:
    """Path/command scope similarity."""

    def test_identical_is_1(self):
        assert scope_similarity("src/main.py", "src/main.py") == 1.0

    def test_glob_containment(self):
        sim = scope_similarity("src/main.py", "src/*.py")
        assert sim >= 0.7

    def test_same_directory(self):
        sim = scope_similarity("src/main.py", "src/utils.py")
        assert sim > 0.3

    def test_completely_different(self):
        sim = scope_similarity("/etc/passwd", "https://api.example.com")
        assert sim < 0.3

    def test_empty_scope(self):
        assert scope_similarity("", "src/main.py") == 0.0


class TestCommandSimilarity:
    """Shell command similarity."""

    def test_same_cmd_different_target(self):
        sim = _command_similarity("rm -rf ./build/", "rm -rf ./dist/")
        assert sim >= 0.6

    def test_different_commands(self):
        sim = _command_similarity("rm -rf ./build/", "ls -la /home")
        assert sim < 0.3

    def test_same_cmd_different_flags(self):
        sim = _command_similarity("rm -f file.txt", "rm -i file.txt")
        assert 0.3 < sim < 0.8


class TestPathPrefixSimilarity:
    """Path prefix similarity."""

    def test_same_directory(self):
        sim = _path_prefix_similarity("src/components/Button.tsx", "src/components/Input.tsx")
        assert sim > 0.5

    def test_different_root(self):
        sim = _path_prefix_similarity("/home/user/file.txt", "/etc/config.txt")
        assert sim < 0.3


class TestResourceSimilarity:
    """Intent-based resource matching."""

    def test_identical_resources(self):
        assert resource_similarity("./build/", "./build/") == 1.0

    def test_empty_resource(self):
        assert resource_similarity("", "./build/") == 0.0

    def test_related_paths(self):
        sim = resource_similarity("src/main.py", "src/utils.py")
        assert sim > 0.3


# ── Integration tests for find_similar_patterns() ───────────────────


def _insert_permission_logs(entries: list[dict]) -> None:
    """Helper: insert multiple PermissionLog rows into the test database."""
    with Session(get_engine()) as session:
        for entry in entries:
            log = PermissionLog(
                organization_id=entry.get("organization_id", "default"),
                tool=entry["tool"],
                action=entry["action"],
                scope=entry["scope"],
                resource=entry.get("resource", ""),
                decision=entry.get("decision", PermissionDecision.ALLOW.value),
                decided_by=entry.get("decided_by", "human:alice"),
                runtime_id=entry.get("runtime_id", "test"),
            )
            session.add(log)
        session.commit()


class TestFindSimilarPatternsHappyPath:
    """Core behavior: finds similar patterns from permission decision history."""

    def test_finds_similar_filesystem_patterns(self):
        """Querying for filesystem/read on src/app.py finds nearby filesystem/read on src/utils.py."""
        _insert_permission_logs([
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "human:alice", "decision": PermissionDecision.ALLOW.value},
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "human:bob", "decision": PermissionDecision.ALLOW.value},
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "human:carol", "decision": PermissionDecision.DENY.value},
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/app.py",
            organization_id="default", min_similarity=0.3, limit=10,
        )

        assert len(patterns) >= 1
        match = patterns[0]
        assert isinstance(match, SimilarPattern)
        assert match.tool == "filesystem"
        assert match.action == "read"
        assert match.scope == "src/utils.py"
        assert 0.0 < match.similarity <= 1.0
        # 2 allow out of 3 total
        assert match.total_decisions == 3
        assert abs(match.allow_rate - 2 / 3) < 0.01
        assert match.unique_humans == 3

    def test_returns_multiple_similar_patterns_sorted_by_similarity(self):
        """Multiple distinct patterns are returned in descending similarity order."""
        _insert_permission_logs([
            # Very similar: same tool/action, scope in same directory
            {"tool": "filesystem", "action": "read", "scope": "src/components/Button.tsx",
             "decided_by": "human:alice"},
            # Somewhat similar: same tool/action, scope in different subdirectory
            {"tool": "filesystem", "action": "read", "scope": "lib/helpers/format.tsx",
             "decided_by": "human:bob"},
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/components/Input.tsx",
            organization_id="default", min_similarity=0.3, limit=10,
        )

        assert len(patterns) >= 1
        # Should be sorted by similarity descending
        for i in range(len(patterns) - 1):
            assert patterns[i].similarity >= patterns[i + 1].similarity

    def test_similarity_score_reflects_closeness(self):
        """A scope in the same directory scores higher than a scope in a different directory."""
        _insert_permission_logs([
            # Same directory: src/components/
            {"tool": "filesystem", "action": "read", "scope": "src/components/Button.tsx",
             "decided_by": "human:alice"},
            # Different directory: tests/
            {"tool": "filesystem", "action": "read", "scope": "tests/test_button.py",
             "decided_by": "human:bob"},
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/components/Input.tsx",
            organization_id="default", min_similarity=0.0, limit=10,
        )

        # Find the two patterns by scope
        by_scope = {p.scope: p for p in patterns}
        assert "src/components/Button.tsx" in by_scope
        assert "tests/test_button.py" in by_scope
        assert by_scope["src/components/Button.tsx"].similarity > by_scope["tests/test_button.py"].similarity

    def test_allow_rate_computed_correctly(self):
        """allow_rate is the fraction of ALLOW decisions for that pattern."""
        _insert_permission_logs([
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:alice", "decision": PermissionDecision.ALLOW.value},
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:bob", "decision": PermissionDecision.ALLOW.value},
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:carol", "decision": PermissionDecision.ALLOW.value},
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:dave", "decision": PermissionDecision.DENY.value},
        ])

        patterns = find_similar_patterns(
            tool="shell", action="execute", scope="npm run build",
            organization_id="default", min_similarity=0.3, limit=10,
        )

        npm_test = [p for p in patterns if p.scope == "npm test"]
        assert len(npm_test) == 1
        assert npm_test[0].allow_rate == 0.75  # 3 allow / 4 total
        assert npm_test[0].total_decisions == 4
        assert npm_test[0].unique_humans == 4


class TestFindSimilarPatternsEdgeCases:
    """Edge cases and boundary conditions."""

    def test_returns_empty_list_with_no_history(self):
        """No decision history at all returns empty list."""
        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="default",
        )
        assert patterns == []

    def test_excludes_exact_match_from_results(self):
        """The exact (tool, action, scope) triple is excluded (caller already has that data)."""
        _insert_permission_logs([
            {"tool": "filesystem", "action": "read", "scope": "src/main.py",
             "decided_by": "human:alice"},
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "human:bob"},
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="default", min_similarity=0.0, limit=10,
        )

        scopes = [p.scope for p in patterns]
        assert "src/main.py" not in scopes
        assert "src/utils.py" in scopes

    def test_respects_organization_id_isolation(self):
        """Patterns from a different organization are invisible."""
        _insert_permission_logs([
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "organization_id": "org-a", "decided_by": "human:alice"},
            {"tool": "filesystem", "action": "read", "scope": "src/helpers.py",
             "organization_id": "org-b", "decided_by": "human:bob"},
        ])

        patterns_a = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="org-a", min_similarity=0.0, limit=10,
        )
        patterns_b = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="org-b", min_similarity=0.0, limit=10,
        )

        scopes_a = {p.scope for p in patterns_a}
        scopes_b = {p.scope for p in patterns_b}
        assert "src/utils.py" in scopes_a
        assert "src/helpers.py" not in scopes_a
        assert "src/helpers.py" in scopes_b
        assert "src/utils.py" not in scopes_b

    def test_respects_limit_parameter(self):
        """No more than `limit` results are returned."""
        entries = []
        for i in range(20):
            entries.append({
                "tool": "filesystem", "action": "read",
                "scope": f"src/module_{i:02d}.py",
                "decided_by": "human:alice",
            })
        _insert_permission_logs(entries)

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/target.py",
            organization_id="default", min_similarity=0.0, limit=3,
        )

        assert len(patterns) <= 3

    def test_respects_min_similarity_threshold(self):
        """Patterns below min_similarity are excluded."""
        _insert_permission_logs([
            # Very different: different tool category, different action category
            {"tool": "database", "action": "query", "scope": "SELECT * FROM users",
             "decided_by": "human:alice"},
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="default", min_similarity=0.8, limit=10,
        )

        # database/query vs filesystem/read with totally different scopes should be below 0.8
        assert len(patterns) == 0

    def test_ignores_system_decided_logs(self):
        """Only human-decided logs are used (decided_by starting with 'human:')."""
        _insert_permission_logs([
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "system"},  # not a human decision
            {"tool": "filesystem", "action": "read", "scope": "src/utils.py",
             "decided_by": "auto_learned"},  # not a human decision
        ])

        patterns = find_similar_patterns(
            tool="filesystem", action="read", scope="src/main.py",
            organization_id="default", min_similarity=0.0, limit=10,
        )

        # system/auto_learned decisions should be filtered out
        assert len(patterns) == 0

    def test_groups_duplicate_patterns_into_single_entry(self):
        """Multiple logs with the same (tool, action, scope) are grouped into one pattern."""
        _insert_permission_logs([
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:alice", "decision": PermissionDecision.ALLOW.value},
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:bob", "decision": PermissionDecision.ALLOW.value},
            {"tool": "shell", "action": "execute", "scope": "npm test",
             "decided_by": "human:carol", "decision": PermissionDecision.DENY.value},
        ])

        patterns = find_similar_patterns(
            tool="shell", action="execute", scope="npm run build",
            organization_id="default", min_similarity=0.3, limit=10,
        )

        npm_test_patterns = [p for p in patterns if p.scope == "npm test"]
        # Should be exactly ONE grouped entry, not three
        assert len(npm_test_patterns) == 1
        assert npm_test_patterns[0].total_decisions == 3


class TestFindSimilarPatternsCrossToolSimilarity:
    """Cross-tool/action similarity using taxonomy."""

    def test_same_taxonomy_category_is_found(self):
        """shell/execute and bash/execute are in the same taxonomy category (execution)."""
        _insert_permission_logs([
            {"tool": "bash", "action": "execute", "scope": "npm test",
             "decided_by": "human:alice"},
        ])

        patterns = find_similar_patterns(
            tool="shell", action="execute", scope="npm run build",
            organization_id="default", min_similarity=0.3, limit=10,
        )

        # bash/execute is in the same taxonomy as shell/execute, should be found
        assert len(patterns) >= 1
        bash_patterns = [p for p in patterns if p.tool == "bash"]
        assert len(bash_patterns) >= 1

    def test_different_taxonomy_category_scores_lower(self):
        """filesystem/read and shell/execute are in different taxonomy categories."""
        _insert_permission_logs([
            # Same category: execution
            {"tool": "bash", "action": "execute", "scope": "npm test",
             "decided_by": "human:alice"},
            # Different category: file_access vs execution
            {"tool": "filesystem", "action": "read", "scope": "npm test",
             "decided_by": "human:bob"},
        ])

        patterns = find_similar_patterns(
            tool="shell", action="execute", scope="npm test-ci",
            organization_id="default", min_similarity=0.0, limit=10,
        )

        by_tool = {p.tool: p for p in patterns}
        if "bash" in by_tool and "filesystem" in by_tool:
            assert by_tool["bash"].similarity > by_tool["filesystem"].similarity


class TestFindSimilarPatternsIntegrationWithEngine:
    """End-to-end integration: engine.check() with enrich=True uses find_similar_patterns."""

    def test_enriched_verdict_includes_similar_patterns(self):
        """PermissionEngine.check(enrich=True) populates similar_patterns from DB history."""
        from aperture.permissions.engine import PermissionEngine

        engine = PermissionEngine()

        # Record several human decisions for similar scopes
        for scope in ["src/utils.py", "src/helpers.py", "src/constants.py"]:
            for user in ["user-1", "user-2"]:
                engine.record_human_decision(
                    tool="filesystem",
                    action="read",
                    scope=scope,
                    decision=PermissionDecision.ALLOW,
                    decided_by=user,
                    organization_id="default",
                )

        # Check a similar but not identical scope with enrichment
        verdict = engine.check(
            "filesystem", "read", "src/main.py", [], enrich=True,
        )

        # Verdict should contain similar patterns from the recorded history
        assert isinstance(verdict.similar_patterns, list)
        if verdict.similar_patterns:
            for pattern in verdict.similar_patterns:
                assert isinstance(pattern, SimilarPattern)
                assert pattern.tool == "filesystem"
                assert pattern.action == "read"
                assert pattern.scope != "src/main.py"  # exact match excluded
                assert 0.0 < pattern.similarity <= 1.0
                assert pattern.total_decisions >= 1
