"""Audit store — append-only event log. Never deletes. Never modifies.

Every permission check, every artifact stored, every human decision
gets an audit event. This is the compliance backbone.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlmodel import Session, select

from aperture.db import get_engine
from aperture.models.audit import AuditEvent

logger = logging.getLogger(__name__)


class AuditStore:
    """Append-only audit trail."""

    def record(
        self,
        event_type: str,
        summary: str,
        *,
        organization_id: str = "default",
        entity_type: str = "",
        entity_id: str = "",
        actor_id: str = "",
        actor_type: str = "",
        runtime_id: str = "",
        details: Optional[dict] = None,
        previous_state: Optional[dict] = None,
        new_state: Optional[dict] = None,
        batch_id: str = "",
    ) -> AuditEvent:
        """Record an audit event. Fire-and-forget — never breaks the caller."""
        event = AuditEvent(
            event_id=uuid.uuid4().hex[:16],
            organization_id=organization_id,
            batch_id=batch_id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            summary=summary,
            actor_id=actor_id,
            actor_type=actor_type,
            runtime_id=runtime_id,
            details=details,
            previous_state=previous_state,
            new_state=new_state,
        )
        try:
            with Session(get_engine()) as session:
                session.add(event)
                session.commit()
                session.refresh(event)
                session.expunge(event)
        except Exception:
            logger.exception("Failed to record audit event: %s", event_type)
        return event

    def list_events(
        self,
        organization_id: str = "default",
        *,
        event_type: Optional[str] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        runtime_id: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """Query audit events with filters."""
        with Session(get_engine()) as session:
            query = select(AuditEvent).where(
                AuditEvent.organization_id == organization_id,
            )
            if event_type:
                query = query.where(AuditEvent.event_type == event_type)
            if entity_type:
                query = query.where(AuditEvent.entity_type == entity_type)
            if entity_id:
                query = query.where(AuditEvent.entity_id == entity_id)
            if actor_id:
                query = query.where(AuditEvent.actor_id == actor_id)
            if runtime_id:
                query = query.where(AuditEvent.runtime_id == runtime_id)
            if since:
                query = query.where(AuditEvent.created_at >= since)  # type: ignore[operator]
            if until:
                query = query.where(AuditEvent.created_at <= until)  # type: ignore[operator]

            query = query.order_by(AuditEvent.created_at.desc()).offset(offset).limit(limit)  # type: ignore[union-attr]
            results = session.exec(query).all()
            for r in results:
                session.expunge(r)
            return list(results)

    def get_event(self, event_id: str) -> Optional[AuditEvent]:
        """Get a single audit event."""
        with Session(get_engine()) as session:
            result = session.exec(
                select(AuditEvent).where(AuditEvent.event_id == event_id)
            ).first()
            if result:
                session.expunge(result)
            return result

    def get_entity_history(
        self,
        entity_type: str,
        entity_id: str,
        organization_id: str = "default",
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Get full history of an entity."""
        with Session(get_engine()) as session:
            results = session.exec(
                select(AuditEvent).where(
                    AuditEvent.organization_id == organization_id,
                    AuditEvent.entity_type == entity_type,
                    AuditEvent.entity_id == entity_id,
                ).order_by(AuditEvent.created_at.desc()).limit(limit)  # type: ignore[union-attr]
            ).all()
            for r in results:
                session.expunge(r)
            return list(results)

    def count(self, organization_id: str = "default") -> int:
        """Count total audit events."""
        with Session(get_engine()) as session:
            result = session.exec(
                select(func.count()).select_from(AuditEvent).where(
                    AuditEvent.organization_id == organization_id,
                )
            ).one()
            return result
