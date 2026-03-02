"""Artifact API — store, retrieve, verify, and track costs.

External runtimes call these endpoints to:
1. Store every output as a verified artifact
2. Retrieve artifacts for audit or review
3. Re-verify artifact integrity
4. Get cost summaries across runtimes/models
"""

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from aperture.stores.artifact_store import ArtifactStore

router = APIRouter()
store = ArtifactStore()


# --- Request/Response schemas ---


class StoreRequest(BaseModel):
    content: str
    artifact_type: str = "custom"
    organization_id: str = "default"
    session_id: str = ""
    task_id: str = ""
    runtime_id: str = ""
    tool_name: str = ""
    tool_args: Optional[dict] = None
    summary: str = ""
    extra: Optional[dict] = None
    tokens_input: int = 0
    tokens_output: int = 0
    cost_usd: float = 0.0
    model_used: str = ""
    provider_used: str = ""


class ArtifactResponse(BaseModel):
    artifact_id: str
    type: str
    content_hash: str
    verification_status: str
    tool_name: str
    summary: str
    tokens_input: int
    tokens_output: int
    cost_usd: float
    model_used: str
    provider_used: str
    created_at: str


# --- Endpoints ---


@router.post("/store", response_model=ArtifactResponse)
def store_artifact(req: StoreRequest):
    """Store an artifact with automatic SHA-256 verification.

    Every tool call, every LLM response, every output from any
    external runtime gets persisted here as the canonical record.
    """
    artifact = store.store(
        content=req.content,
        artifact_type=req.artifact_type,
        organization_id=req.organization_id,
        session_id=req.session_id,
        task_id=req.task_id,
        runtime_id=req.runtime_id,
        tool_name=req.tool_name,
        tool_args=req.tool_args,
        summary=req.summary,
        extra=req.extra,
        tokens_input=req.tokens_input,
        tokens_output=req.tokens_output,
        cost_usd=req.cost_usd,
        model_used=req.model_used,
        provider_used=req.provider_used,
    )
    return ArtifactResponse(
        artifact_id=artifact.artifact_id,
        type=artifact.type,
        content_hash=artifact.content_hash,
        verification_status=artifact.verification_status,
        tool_name=artifact.tool_name,
        summary=artifact.summary,
        tokens_input=artifact.tokens_input,
        tokens_output=artifact.tokens_output,
        cost_usd=artifact.cost_usd,
        model_used=artifact.model_used,
        provider_used=artifact.provider_used,
        created_at=artifact.created_at.isoformat(),
    )


@router.get("/costs/summary")
def cost_summary(
    organization_id: str = "default",
    task_id: Optional[str] = None,
    runtime_id: Optional[str] = None,
):
    """Get cost summary across artifacts.

    Breaks down by provider and model. Shows total tokens and cost.
    """
    return store.get_cost_summary(
        organization_id=organization_id,
        task_id=task_id,
        runtime_id=runtime_id,
    )


@router.get("/task/{task_id}")
def list_by_task(task_id: str, organization_id: str = "default"):
    """List all artifacts for a task."""
    artifacts = store.list_by_task(task_id, organization_id)
    return {
        "task_id": task_id,
        "count": len(artifacts),
        "artifacts": [
            {
                "artifact_id": a.artifact_id,
                "type": a.type,
                "content_hash": a.content_hash,
                "verification_status": a.verification_status,
                "tool_name": a.tool_name,
                "summary": a.summary,
                "cost_usd": a.cost_usd,
                "created_at": a.created_at.isoformat(),
            }
            for a in artifacts
        ],
    }


@router.get("/{artifact_id}")
def get_artifact(artifact_id: str):
    """Retrieve a stored artifact."""
    artifact = store.get(artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return {
        "artifact_id": artifact.artifact_id,
        "type": artifact.type,
        "content_hash": artifact.content_hash,
        "verification_status": artifact.verification_status,
        "content": artifact.content if artifact.storage_backend == "inline" else None,
        "tool_name": artifact.tool_name,
        "tool_args": artifact.tool_args,
        "summary": artifact.summary,
        "extra": artifact.extra,
        "tokens_input": artifact.tokens_input,
        "tokens_output": artifact.tokens_output,
        "cost_usd": artifact.cost_usd,
        "model_used": artifact.model_used,
        "provider_used": artifact.provider_used,
        "runtime_id": artifact.runtime_id,
        "created_at": artifact.created_at.isoformat(),
    }


@router.post("/{artifact_id}/verify")
def verify_artifact(artifact_id: str):
    """Re-verify an artifact's integrity.

    Recomputes SHA-256 hash and compares to stored hash.
    Returns current verification status.
    """
    try:
        artifact = store.verify(artifact_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return {
        "artifact_id": artifact.artifact_id,
        "verification_status": artifact.verification_status,
        "content_hash": artifact.content_hash,
        "verified_at": artifact.verified_at.isoformat() if artifact.verified_at else None,
    }
