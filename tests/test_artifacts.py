"""Tests for artifact storage and verification."""

from aperture.models.artifact import ArtifactType, VerificationStatus
from aperture.stores.artifact_store import ArtifactStore


class TestArtifactStore:

    def test_store_and_retrieve(self):
        store = ArtifactStore()
        artifact = store.store(
            content="print('hello world')",
            artifact_type=ArtifactType.TOOL_CALL,
            tool_name="shell",
            summary="ran hello world",
        )
        assert artifact.artifact_id
        assert artifact.content_hash
        assert artifact.verification_status == VerificationStatus.VERIFIED

        retrieved = store.get(artifact.artifact_id)
        assert retrieved is not None
        assert retrieved.content == "print('hello world')"
        assert retrieved.content_hash == artifact.content_hash

    def test_hash_verification(self):
        store = ArtifactStore()
        artifact = store.store(content="original content")

        # Re-verify — should pass
        verified = store.verify(artifact.artifact_id)
        assert verified.verification_status == VerificationStatus.VERIFIED

    def test_cost_tracking(self):
        store = ArtifactStore()
        store.store(
            content="response 1",
            tokens_input=100,
            tokens_output=50,
            cost_usd=0.003,
            model_used="claude-sonnet",
            provider_used="anthropic",
            runtime_id="runtime-1",
        )
        store.store(
            content="response 2",
            tokens_input=200,
            tokens_output=100,
            cost_usd=0.006,
            model_used="gpt-4o",
            provider_used="openai",
            runtime_id="runtime-1",
        )

        summary = store.get_cost_summary()
        assert abs(summary["total_cost_usd"] - 0.009) < 1e-9
        assert summary["total_tokens_input"] == 300
        assert summary["total_artifacts"] == 2
        assert summary["by_provider"]["anthropic"] == 0.003
        assert summary["by_provider"]["openai"] == 0.006

    def test_list_by_task(self):
        store = ArtifactStore()
        store.store(content="a1", task_id="task-1")
        store.store(content="a2", task_id="task-1")
        store.store(content="a3", task_id="task-2")

        task_1_artifacts = store.list_by_task("task-1")
        assert len(task_1_artifacts) == 2

        task_2_artifacts = store.list_by_task("task-2")
        assert len(task_2_artifacts) == 1
