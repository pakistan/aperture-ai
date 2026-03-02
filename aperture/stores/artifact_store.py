"""Artifact store — persists and retrieves verified AI agent outputs.

Every artifact is SHA-256 hashed on storage. Integrity can be
re-verified at any time without an LLM.
"""

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.artifact import (
    Artifact,
    ArtifactType,
    VerificationMethod,
    VerificationStatus,
)

logger = logging.getLogger(__name__)


class ArtifactStore:
    """Persist and retrieve artifacts with hash verification."""

    def store(
        self,
        content: str,
        *,
        artifact_type: str = ArtifactType.CUSTOM,
        organization_id: str = "default",
        session_id: str = "",
        task_id: str = "",
        runtime_id: str = "",
        tool_name: str = "",
        tool_args: Optional[dict] = None,
        summary: str = "",
        extra: Optional[dict] = None,
        tokens_input: int = 0,
        tokens_output: int = 0,
        cost_usd: float = 0.0,
        model_used: str = "",
        provider_used: str = "",
    ) -> Artifact:
        """Store an artifact with automatic SHA-256 hashing.

        Args:
            content: The artifact content (inline storage)
            artifact_type: Type classification
            organization_id: Tenant ID
            session_id: Session grouping
            task_id: Task association
            runtime_id: Which external runtime produced this
            tool_name: Tool that produced this (if tool_call type)
            tool_args: Arguments passed to the tool
            summary: Human-readable summary
            extra: Additional metadata
            tokens_input: Input tokens reported by runtime
            tokens_output: Output tokens reported by runtime
            cost_usd: Cost reported by runtime
            model_used: Model that produced this
            provider_used: Provider that produced this

        Returns:
            The persisted Artifact with ID and hash
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        artifact = Artifact(
            artifact_id=uuid.uuid4().hex[:16],
            organization_id=organization_id,
            session_id=session_id,
            task_id=task_id,
            runtime_id=runtime_id,
            type=artifact_type,
            content=content,
            content_hash=content_hash,
            storage_backend="inline",
            verification_method=VerificationMethod.HASH_CHECK,
            verification_status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(timezone.utc).replace(tzinfo=None),
            tool_name=tool_name,
            tool_args=tool_args,
            summary=summary,
            extra=extra,
            tokens_input=tokens_input,
            tokens_output=tokens_output,
            cost_usd=cost_usd,
            model_used=model_used,
            provider_used=provider_used,
        )

        with Session(get_engine()) as session:
            session.add(artifact)
            session.commit()
            session.refresh(artifact)
            session.expunge(artifact)

        return artifact

    def get(self, artifact_id: str) -> Optional[Artifact]:
        """Retrieve an artifact by ID."""
        with Session(get_engine()) as session:
            result = session.exec(
                select(Artifact).where(Artifact.artifact_id == artifact_id)
            ).first()
            if result:
                session.expunge(result)
            return result

    def list_by_task(
        self, task_id: str, organization_id: str = "default"
    ) -> list[Artifact]:
        """List all artifacts for a task."""
        with Session(get_engine()) as session:
            results = session.exec(
                select(Artifact).where(
                    Artifact.task_id == task_id,
                    Artifact.organization_id == organization_id,
                ).order_by(Artifact.created_at.desc())  # type: ignore[union-attr]
            ).all()
            for r in results:
                session.expunge(r)
            return list(results)

    def verify(self, artifact_id: str) -> Artifact:
        """Re-verify an artifact's integrity.

        Recomputes the hash and compares to stored hash.
        Updates verification_status in-place.
        """
        with Session(get_engine()) as session:
            artifact = session.exec(
                select(Artifact).where(Artifact.artifact_id == artifact_id)
            ).first()
            if not artifact:
                msg = f"Artifact not found: {artifact_id}"
                raise ValueError(msg)

            if artifact.storage_backend == "inline":
                current_hash = hashlib.sha256(artifact.content.encode()).hexdigest()
            elif artifact.storage_backend == "local_fs":
                path = Path(artifact.storage_path)
                if not path.exists():
                    artifact.verification_status = VerificationStatus.FAILED
                    session.add(artifact)
                    session.commit()
                    session.refresh(artifact)
                    session.expunge(artifact)
                    return artifact
                current_hash = hashlib.sha256(path.read_text().encode()).hexdigest()
            else:
                artifact.verification_status = VerificationStatus.UNVERIFIED
                session.expunge(artifact)
                return artifact

            if current_hash == artifact.content_hash:
                artifact.verification_status = VerificationStatus.VERIFIED
                artifact.verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
            else:
                artifact.verification_status = VerificationStatus.FAILED

            session.add(artifact)
            session.commit()
            session.refresh(artifact)
            session.expunge(artifact)
            return artifact

    def get_cost_summary(
        self,
        organization_id: str = "default",
        task_id: Optional[str] = None,
        runtime_id: Optional[str] = None,
    ) -> dict:
        """Get cost summary across artifacts."""
        with Session(get_engine()) as session:
            query = select(Artifact).where(
                Artifact.organization_id == organization_id,
            )
            if task_id:
                query = query.where(Artifact.task_id == task_id)
            if runtime_id:
                query = query.where(Artifact.runtime_id == runtime_id)

            artifacts = session.exec(query).all()

        total_cost = sum(a.cost_usd for a in artifacts)
        total_input = sum(a.tokens_input for a in artifacts)
        total_output = sum(a.tokens_output for a in artifacts)

        by_provider: dict[str, float] = {}
        by_model: dict[str, float] = {}
        for a in artifacts:
            if a.provider_used:
                by_provider[a.provider_used] = by_provider.get(a.provider_used, 0) + a.cost_usd
            if a.model_used:
                by_model[a.model_used] = by_model.get(a.model_used, 0) + a.cost_usd

        return {
            "total_cost_usd": total_cost,
            "total_tokens_input": total_input,
            "total_tokens_output": total_output,
            "total_artifacts": len(artifacts),
            "by_provider": by_provider,
            "by_model": by_model,
        }
