"""Tests for the config API endpoints (GET /config, PATCH /config)."""

from fastapi.testclient import TestClient

import aperture.config
from aperture.api import create_app


class TestGetConfig:

    def test_get_config_returns_settings_and_descriptions(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "settings" in data
        assert "descriptions" in data
        assert isinstance(data["settings"], dict)
        assert isinstance(data["descriptions"], dict)

    def test_get_config_returns_all_tunable_fields(self):
        app = create_app()
        client = TestClient(app)
        resp = client.get("/config")
        data = resp.json()
        for field in aperture.config.Settings.TUNABLE_FIELDS:
            assert field in data["settings"], f"Missing tunable field: {field}"
            assert field in data["descriptions"], f"Missing description for: {field}"

    def test_get_config_excludes_infra_fields(self):
        """Infrastructure fields like db_path, api_host should not appear."""
        app = create_app()
        client = TestClient(app)
        resp = client.get("/config")
        data = resp.json()
        for infra_field in ("db_path", "db_backend", "api_host", "api_port", "postgres_url"):
            assert infra_field not in data["settings"]

    def test_get_config_reflects_current_values(self):
        app = create_app()
        client = TestClient(app)
        # Set a known value
        aperture.config.settings.auto_approve_threshold = 0.88
        resp = client.get("/config")
        data = resp.json()
        assert data["settings"]["auto_approve_threshold"] == 0.88


class TestPatchConfig:

    def test_patch_single_field(self):
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={
            "settings": {"auto_approve_threshold": 0.80},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["updated"] is True
        assert data["settings"]["auto_approve_threshold"] == 0.80
        # Verify in-memory update
        assert aperture.config.settings.auto_approve_threshold == 0.80

    def test_patch_multiple_fields(self):
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={
            "settings": {
                "permission_learning_min_decisions": 3,
                "intelligence_enabled": True,
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["settings"]["permission_learning_min_decisions"] == 3
        assert data["settings"]["intelligence_enabled"] is True

    def test_patch_rejects_infra_fields(self):
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={
            "settings": {"db_path": "/tmp/evil.db"},
        })
        assert resp.status_code == 400
        assert "non-tunable" in resp.json()["detail"].lower()

    def test_patch_rejects_approve_below_deny(self):
        """auto_approve_threshold must be > auto_deny_threshold."""
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={
            "settings": {
                "auto_approve_threshold": 0.01,
                "auto_deny_threshold": 0.99,
            },
        })
        assert resp.status_code == 400
        assert "must be greater" in resp.json()["detail"].lower()

    def test_patch_rejects_approve_equals_deny(self):
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={
            "settings": {
                "auto_approve_threshold": 0.50,
                "auto_deny_threshold": 0.50,
            },
        })
        assert resp.status_code == 400

    def test_patch_empty_settings_is_ok(self):
        app = create_app()
        client = TestClient(app)
        resp = client.patch("/config", json={"settings": {}})
        assert resp.status_code == 200
        assert resp.json()["updated"] is True

    def test_patch_persists_to_env_file(self, tmp_path):
        """PATCH writes .aperture.env file."""
        env_path = tmp_path / ".aperture.env"
        # Monkey-patch update_settings to use tmp env file
        original_update = aperture.config.update_settings

        def patched_update(updates, env_file_path=None):
            return original_update(updates, env_file_path=str(env_path))

        aperture.config.update_settings = patched_update
        try:
            app = create_app()
            client = TestClient(app)
            client.patch("/config", json={
                "settings": {"intelligence_epsilon": 2.5},
            })
            content = env_path.read_text()
            assert "APERTURE_INTELLIGENCE_EPSILON=2.5" in content
        finally:
            aperture.config.update_settings = original_update

    def test_get_after_patch_reflects_update(self):
        """GET /config after PATCH returns the updated values."""
        app = create_app()
        client = TestClient(app)
        client.patch("/config", json={
            "settings": {"permission_learning_min_decisions": 42},
        })
        resp = client.get("/config")
        assert resp.json()["settings"]["permission_learning_min_decisions"] == 42


class TestConfigUnit:

    def test_get_tunable_config(self):
        config = aperture.config.get_tunable_config()
        assert set(config.keys()) == aperture.config.Settings.TUNABLE_FIELDS

    def test_update_settings_rejects_unknown_field(self, tmp_path):
        with __import__("pytest").raises(ValueError, match="(?i)non-tunable"):
            aperture.config.update_settings(
                {"api_port": 9999},
                env_file_path=str(tmp_path / ".env"),
            )

    def test_write_env_file(self, tmp_path):
        env_path = tmp_path / ".aperture.env"
        aperture.config._write_env_file(str(env_path))
        content = env_path.read_text()
        assert "APERTURE_AUTO_APPROVE_THRESHOLD=" in content
        assert "APERTURE_PERMISSION_LEARNING_ENABLED=" in content
