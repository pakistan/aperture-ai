"""Artifact models — verified, hash-checked records of every AI agent output."""

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Column, Field, JSON, SQLModel


class ArtifactType(str, enum.Enum):
    TOOL_CALL = "tool_call"  # a tool invocation + response
    TOOL_RESPONSE = "tool_response"
    LLM_RESPONSE = "llm_response"
    DECISION = "decision"
    FILE = "file"
    MESSAGE = "message"
    CUSTOM = "custom"


class VerificationMethod(str, enum.Enum):
    HASH_CHECK = "hash_check"
    SCHEMA_CHECK = "schema_check"
    NONE = "none"


class VerificationStatus(str, enum.Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"


class Artifact(SQLModel, table=True):
    """Immutable record of an AI agent output. SHA-256 integrity checked."""

    __tablename__ = "artifacts"

    id: Optional[int] = Field(default=None, primary_key=True)
    artifact_id: str = Field(index=True, unique=True)
    organization_id: str = Field(default="default", index=True)
    session_id: str = Field(default="", index=True)
    task_id: str = Field(default="", index=True)
    runtime_id: str = Field(default="", index=True)  # which external runtime produced this

    # Content
    type: str = ArtifactType.CUSTOM
    content_hash: str = ""  # SHA-256
    storage_backend: str = "inline"  # "inline" | "local_fs"
    storage_path: str = ""  # path for local_fs
    content: str = ""  # inline content

    # Verification
    verification_method: str = VerificationMethod.NONE
    verification_status: str = VerificationStatus.UNVERIFIED
    verified_at: Optional[datetime] = None

    # Metadata
    tool_name: str = ""  # if type=tool_call, which tool
    tool_args: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    summary: str = ""
    extra: Optional[dict] = Field(default=None, sa_column=Column(JSON))

    # Cost tracking (reported by external runtime)
    tokens_input: int = 0
    tokens_output: int = 0
    cost_usd: float = 0.0
    model_used: str = ""
    provider_used: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
