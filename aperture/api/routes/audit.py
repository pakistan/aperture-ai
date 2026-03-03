"""Audit API — immutable event trail.

Everything that happens in Aperture is logged here.
This is the compliance backbone.
"""

from datetime import datetime

from fastapi import APIRouter, HTTPException

from aperture.stores.audit_store import AuditStore

router = APIRouter()
store = AuditStore()


@router.get("/events")
def list_events(
    organization_id: str = "default",
    event_type: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    actor_id: str | None = None,
    runtime_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    """Query audit events with filters."""
    limit = min(limit, 1000)
    try:
        since_dt = datetime.fromisoformat(since) if since else None
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid 'since' date format: {since!r}")
    try:
        until_dt = datetime.fromisoformat(until) if until else None
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid 'until' date format: {until!r}")

    events = store.list_events(
        organization_id=organization_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_id=actor_id,
        runtime_id=runtime_id,
        since=since_dt,
        until=until_dt,
        limit=limit,
        offset=offset,
    )
    return {
        "count": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "summary": e.summary,
                "actor_id": e.actor_id,
                "actor_type": e.actor_type,
                "runtime_id": e.runtime_id,
                "details": e.details,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/events/{event_id}")
def get_event(event_id: str):
    """Get a single audit event with full details."""
    event = store.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Audit event not found")
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "summary": event.summary,
        "actor_id": event.actor_id,
        "actor_type": event.actor_type,
        "runtime_id": event.runtime_id,
        "details": event.details,
        "previous_state": event.previous_state,
        "new_state": event.new_state,
        "created_at": event.created_at.isoformat(),
    }


@router.get("/entity/{entity_type}/{entity_id}")
def entity_history(
    entity_type: str,
    entity_id: str,
    organization_id: str = "default",
    limit: int = 50,
):
    """Full audit history of a specific entity."""
    limit = min(limit, 1000)
    events = store.get_entity_history(entity_type, entity_id, organization_id, limit)
    return {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "count": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "summary": e.summary,
                "actor_id": e.actor_id,
                "details": e.details,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    }


@router.get("/count")
def event_count(organization_id: str = "default"):
    """Total audit event count."""
    return {"count": store.count(organization_id)}
