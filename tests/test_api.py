"""Tests for the API endpoints."""

from fastapi.testclient import TestClient

from aperture.api import create_app


class TestHealthEndpoint:

    def test_health(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["service"] == "aperture"


class TestPermissionAPI:

    def test_check_with_allow_rule(self):
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/check", json={
            "tool": "filesystem",
            "action": "read",
            "scope": "src/main.py",
            "permissions": [
                {"tool": "filesystem", "action": "read", "scope": "src/*", "decision": "allow"}
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert "risk" in data
        assert data["risk"]["tier"] in ("low", "medium", "high", "critical")

    def test_check_with_deny(self):
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/check", json={
            "tool": "shell",
            "action": "execute",
            "scope": "rm -rf /",
            "permissions": [],  # no rules = deny
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["risk"]["tier"] == "critical"

    def test_check_enriched(self):
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/check?enrich=true", json={
            "tool": "shell",
            "action": "execute",
            "scope": "ls -la",
            "permissions": [
                {"tool": "shell", "action": "execute", "scope": "*", "decision": "allow"}
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"
        assert data["explanation"]

    def test_record_and_patterns(self):
        app = create_app()
        client = TestClient(app)

        # Record 10 decisions
        for i in range(10):
            client.post("/permissions/record", json={
                "tool": "api",
                "action": "get",
                "scope": "users/*",
                "decision": "allow",
                "decided_by": f"user-{i % 3}",
            })

        # Check patterns
        resp = client.get("/permissions/patterns?min_decisions=5")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert data["patterns"][0]["approval_rate"] == 1.0
        assert "weighted_approval_rate" in data["patterns"][0]
        assert "recommendation_text" in data["patterns"][0]

    def test_explain_endpoint(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/permissions/explain?tool=shell&action=execute&scope=rm%20-rf%20./build/")
        assert resp.status_code == 200
        data = resp.json()
        assert "explanation" in data
        assert "risk" in data
        assert data["risk"]["tier"] in ("low", "medium", "high", "critical")

    def test_stats_endpoint(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/permissions/stats")
        assert resp.status_code == 200

    # --- Route 1: POST /permissions/grant ---

    def test_grant_task_permission_happy_path(self):
        """Granting a task-scoped permission returns granted=True and a permission_id."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/grant", json={
            "task_id": "task-abc-123",
            "tool": "filesystem",
            "action": "write",
            "scope": "src/*.py",
            "decision": "allow",
            "granted_by": "human-reviewer-1",
            "organization_id": "acme-corp",
            "ttl_seconds": 3600,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["granted"] is True
        assert isinstance(data["permission_id"], str)
        assert len(data["permission_id"]) > 0

    def test_grant_task_permission_deny_decision(self):
        """Granting a deny decision works the same as allow."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/grant", json={
            "task_id": "task-deny-456",
            "tool": "shell",
            "action": "execute",
            "scope": "rm -rf *",
            "decision": "deny",
            "granted_by": "security-admin",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["granted"] is True
        assert isinstance(data["permission_id"], str)

    def test_grant_task_permission_no_ttl(self):
        """Granting without a TTL (ttl_seconds=null) succeeds."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/grant", json={
            "task_id": "task-no-ttl",
            "tool": "api",
            "action": "get",
            "scope": "users/*",
            "decision": "allow",
            "granted_by": "ops-team",
            "ttl_seconds": None,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["granted"] is True

    def test_grant_used_by_check_rebac(self):
        """A granted permission is actually used during /permissions/check via ReBAC."""
        app = create_app()
        client = TestClient(app)

        # Grant a task-scoped permission
        grant_resp = client.post("/permissions/grant", json={
            "task_id": "task-rebac-test",
            "tool": "database",
            "action": "read",
            "scope": "users.*",
            "decision": "allow",
            "granted_by": "dba-alice",
        })
        assert grant_resp.status_code == 200

        # Now check with task_id -- should resolve via ReBAC, not static rules
        check_resp = client.post("/permissions/check", json={
            "tool": "database",
            "action": "read",
            "scope": "users.email",
            "permissions": [],  # no static rules = would be deny
            "task_id": "task-rebac-test",
        })
        assert check_resp.status_code == 200
        check_data = check_resp.json()
        assert check_data["decision"] == "allow"
        assert check_data["decided_by"] == "rebac"

    def test_grant_invalid_decision_rejected(self):
        """An invalid decision value (not allow/deny) returns 422 validation error."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/grant", json={
            "task_id": "task-bad",
            "tool": "shell",
            "action": "execute",
            "scope": "*",
            "decision": "maybe",
            "granted_by": "user",
        })
        assert resp.status_code == 422

    def test_grant_missing_required_field(self):
        """Missing required field (task_id) returns 422 validation error."""
        app = create_app()
        client = TestClient(app)
        resp = client.post("/permissions/grant", json={
            # task_id missing
            "tool": "shell",
            "action": "execute",
            "scope": "*",
            "decision": "allow",
            "granted_by": "user",
        })
        assert resp.status_code == 422

    # --- Route 2: GET /permissions/similar ---

    def test_similar_no_history(self):
        """With no decision history, similar returns empty patterns list."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/permissions/similar?tool=custom&action=run&scope=test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["patterns"] == []

    def test_similar_finds_related_patterns(self):
        """After recording decisions, /similar finds structurally similar patterns."""
        app = create_app()
        client = TestClient(app)

        # Record decisions for shell.execute on "rm -rf ./build/"
        for i in range(5):
            client.post("/permissions/record", json={
                "tool": "shell",
                "action": "execute",
                "scope": "rm -rf ./build/",
                "decision": "allow",
                "decided_by": f"user-{i}",
            })

        # Query for similar pattern: shell.execute on "rm -rf ./dist/"
        # Same command, different target -- high similarity expected
        resp = client.get(
            "/permissions/similar?tool=shell&action=execute&scope=rm%20-rf%20./dist/"
            "&min_similarity=0.3"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        pattern = data["patterns"][0]
        assert pattern["tool"] == "shell"
        assert pattern["action"] == "execute"
        assert pattern["scope"] == "rm -rf ./build/"
        assert 0.0 <= pattern["similarity"] <= 1.0
        assert 0.0 <= pattern["allow_rate"] <= 1.0
        assert pattern["total_decisions"] == 5
        assert "unique_humans" in pattern

    def test_similar_response_shape(self):
        """Each pattern in the response has the correct fields and types."""
        app = create_app()
        client = TestClient(app)

        # Seed some decisions
        for i in range(3):
            client.post("/permissions/record", json={
                "tool": "filesystem",
                "action": "read",
                "scope": "src/main.py",
                "decision": "allow" if i < 2 else "deny",
                "decided_by": f"reviewer-{i}",
            })

        # Query a similar filesystem read
        resp = client.get(
            "/permissions/similar?tool=filesystem&action=read&scope=src/utils.py"
            "&min_similarity=0.3"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert isinstance(data["patterns"], list)

        if data["count"] > 0:
            p = data["patterns"][0]
            required_keys = {"tool", "action", "scope", "similarity", "allow_rate",
                             "total_decisions", "unique_humans"}
            assert required_keys.issubset(p.keys())
            assert isinstance(p["similarity"], float)
            assert isinstance(p["allow_rate"], float)
            assert isinstance(p["total_decisions"], int)
            assert isinstance(p["unique_humans"], int)

    def test_similar_missing_required_params(self):
        """Omitting required query params (tool, action, scope) returns 422."""
        app = create_app()
        client = TestClient(app)
        # Missing scope
        resp = client.get("/permissions/similar?tool=shell&action=execute")
        assert resp.status_code == 422


class TestIntelligenceAPI:

    def test_global_signal_no_data(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/intelligence/global-signal?tool=custom&action=unknown&scope=test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["available"] is False


class TestArtifactAPI:

    def test_store_and_retrieve(self):
        app = create_app()
        client = TestClient(app)

        # Store
        resp = client.post("/artifacts/store", json={
            "content": "test output",
            "artifact_type": "tool_call",
            "tool_name": "shell",
            "summary": "ran a test",
        })
        assert resp.status_code == 200
        artifact_id = resp.json()["artifact_id"]
        assert resp.json()["verification_status"] == "verified"

        # Retrieve
        resp = client.get(f"/artifacts/{artifact_id}")
        assert resp.status_code == 200
        assert resp.json()["content"] == "test output"

    def test_verify_endpoint(self):
        app = create_app()
        client = TestClient(app)

        resp = client.post("/artifacts/store", json={"content": "verify me"})
        artifact_id = resp.json()["artifact_id"]

        resp = client.post(f"/artifacts/{artifact_id}/verify")
        assert resp.status_code == 200
        assert resp.json()["verification_status"] == "verified"

    def test_cost_summary(self):
        app = create_app()
        client = TestClient(app)

        client.post("/artifacts/store", json={
            "content": "r1",
            "tokens_input": 100,
            "cost_usd": 0.01,
            "provider_used": "anthropic",
        })

        resp = client.get("/artifacts/costs/summary")
        assert resp.status_code == 200
        assert resp.json()["total_cost_usd"] == 0.01

    # --- Route 3: GET /artifacts/task/{task_id} ---

    def test_list_artifacts_by_task_empty(self):
        """Listing artifacts for a task with no stored artifacts returns empty list."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/artifacts/task/nonexistent-task-xyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["task_id"] == "nonexistent-task-xyz"
        assert data["count"] == 0
        assert data["artifacts"] == []

    def test_list_artifacts_by_task_returns_stored(self):
        """Artifacts stored with a task_id are returned by the task listing endpoint."""
        app = create_app()
        client = TestClient(app)
        task_id = "task-artifact-list-001"

        # Store two artifacts for the same task
        resp1 = client.post("/artifacts/store", json={
            "content": "first output",
            "artifact_type": "tool_call",
            "tool_name": "shell",
            "summary": "step 1",
            "task_id": task_id,
        })
        assert resp1.status_code == 200
        id1 = resp1.json()["artifact_id"]

        resp2 = client.post("/artifacts/store", json={
            "content": "second output",
            "artifact_type": "llm_response",
            "tool_name": "text_response",
            "summary": "step 2",
            "task_id": task_id,
        })
        assert resp2.status_code == 200
        id2 = resp2.json()["artifact_id"]

        # Store an artifact for a DIFFERENT task (should not appear)
        client.post("/artifacts/store", json={
            "content": "other task output",
            "task_id": "other-task-999",
        })

        # List by task
        resp = client.get(f"/artifacts/task/{task_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["task_id"] == task_id
        assert data["count"] == 2
        assert len(data["artifacts"]) == 2

        returned_ids = {a["artifact_id"] for a in data["artifacts"]}
        assert id1 in returned_ids
        assert id2 in returned_ids

    def test_list_artifacts_by_task_response_shape(self):
        """Each artifact in the task listing has the expected fields."""
        app = create_app()
        client = TestClient(app)
        task_id = "task-shape-check"

        client.post("/artifacts/store", json={
            "content": "shape test",
            "artifact_type": "tool_call",
            "tool_name": "pytest",
            "summary": "test run",
            "task_id": task_id,
            "cost_usd": 0.005,
        })

        resp = client.get(f"/artifacts/task/{task_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1

        artifact = data["artifacts"][0]
        required_keys = {
            "artifact_id", "type", "content_hash", "verification_status",
            "tool_name", "summary", "cost_usd", "created_at",
        }
        assert required_keys.issubset(artifact.keys())
        assert artifact["verification_status"] == "verified"
        assert artifact["tool_name"] == "pytest"
        assert artifact["cost_usd"] == 0.005
        assert artifact["created_at"]  # non-empty ISO timestamp


class TestAuditAPI:

    def test_events_endpoint(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/audit/events")
        assert resp.status_code == 200

    def test_count_endpoint(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/audit/count")
        assert resp.status_code == 200
        assert "count" in resp.json()

    # --- Route 4: GET /audit/events/{event_id} ---

    def test_get_audit_event_not_found(self):
        """Fetching a nonexistent audit event returns 404."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/audit/events/nonexistent-event-id-abc")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_get_audit_event_happy_path(self):
        """An audit event created by a permission check can be retrieved by its event_id."""
        from aperture.stores.audit_store import AuditStore

        app = create_app()
        client = TestClient(app)

        # Directly create an audit event with known properties
        audit_store = AuditStore()
        event = audit_store.record(
            "permission.check",
            "Checked filesystem read on config.yaml",
            entity_type="permission",
            entity_id="perm-test-1",
            actor_id="runtime-test",
            actor_type="runtime",
            runtime_id="claude-code-1",
            details={"tool": "filesystem", "action": "read"},
        )
        event_id = event.event_id

        # Fetch the specific event by ID
        resp = client.get(f"/audit/events/{event_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["event_id"] == event_id
        assert data["event_type"] == "permission.check"
        assert data["summary"] == "Checked filesystem read on config.yaml"
        assert data["actor_id"] == "runtime-test"
        assert data["actor_type"] == "runtime"
        assert data["runtime_id"] == "claude-code-1"
        assert "created_at" in data

    def test_get_audit_event_response_includes_state_fields(self):
        """The single-event endpoint returns previous_state and new_state fields."""
        from aperture.stores.audit_store import AuditStore

        app = create_app()
        client = TestClient(app)

        # Create an audit event with state change data
        audit_store = AuditStore()
        event = audit_store.record(
            "permission.granted",
            "Granted shell execute to task-1",
            previous_state={"status": "pending"},
            new_state={"status": "active"},
            details={"tool": "shell"},
        )

        resp = client.get(f"/audit/events/{event.event_id}")
        assert resp.status_code == 200
        data = resp.json()

        # Single-event endpoint includes state fields that list endpoint does not
        assert "previous_state" in data
        assert "new_state" in data
        assert data["previous_state"] == {"status": "pending"}
        assert data["new_state"] == {"status": "active"}
        assert "actor_id" in data
        assert "actor_type" in data
        assert "runtime_id" in data
        assert "details" in data

    # --- Route 5: GET /audit/entity/{entity_type}/{entity_id} ---

    def test_entity_history_empty(self):
        """Entity history for a nonexistent entity returns empty list, not 404."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/audit/entity/task/nonexistent-task-999")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_type"] == "task"
        assert data["entity_id"] == "nonexistent-task-999"
        assert data["count"] == 0
        assert data["events"] == []

    def test_entity_history_returns_matching_events(self):
        """Events recorded with entity_type/entity_id appear in entity history."""
        from aperture.stores.audit_store import AuditStore

        app = create_app()
        client = TestClient(app)

        # Directly record audit events with specific entity_type/entity_id
        audit_store = AuditStore()
        audit_store.record(
            "permission.granted",
            "Granted filesystem write to task-ent-1",
            entity_type="task",
            entity_id="task-ent-1",
            actor_id="reviewer-alice",
            details={"tool": "filesystem", "action": "write"},
        )
        audit_store.record(
            "artifact.stored",
            "Stored output for task-ent-1",
            entity_type="task",
            entity_id="task-ent-1",
            actor_id="runtime-claude",
        )
        # Different entity -- should NOT appear
        audit_store.record(
            "permission.granted",
            "Granted for different task",
            entity_type="task",
            entity_id="task-ent-OTHER",
            actor_id="reviewer-bob",
        )

        resp = client.get("/audit/entity/task/task-ent-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entity_type"] == "task"
        assert data["entity_id"] == "task-ent-1"
        assert data["count"] == 2
        assert len(data["events"]) == 2

        # Verify each event has expected fields
        for event in data["events"]:
            required_keys = {"event_id", "event_type", "summary", "actor_id",
                             "details", "created_at"}
            assert required_keys.issubset(event.keys()), (
                f"Missing keys: {required_keys - event.keys()}"
            )

    def test_entity_history_respects_entity_type(self):
        """Events with the same entity_id but different entity_type are not returned."""
        from aperture.stores.audit_store import AuditStore

        app = create_app()
        client = TestClient(app)

        audit_store = AuditStore()
        audit_store.record(
            "task.completed",
            "Task completed",
            entity_type="task",
            entity_id="shared-id-42",
        )
        audit_store.record(
            "artifact.verified",
            "Artifact verified",
            entity_type="artifact",
            entity_id="shared-id-42",
        )

        # Query for entity_type=task only
        resp = client.get("/audit/entity/task/shared-id-42")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["events"][0]["event_type"] == "task.completed"

        # Query for entity_type=artifact only
        resp = client.get("/audit/entity/artifact/shared-id-42")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["events"][0]["event_type"] == "artifact.verified"

    def test_entity_history_response_shape(self):
        """The entity history response includes entity_type, entity_id, count, and events list."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/audit/entity/permission/perm-123")
        assert resp.status_code == 200
        data = resp.json()
        assert "entity_type" in data
        assert "entity_id" in data
        assert "count" in data
        assert "events" in data
        assert isinstance(data["events"], list)
        assert isinstance(data["count"], int)
