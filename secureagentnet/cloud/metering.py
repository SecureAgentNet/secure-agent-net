"""Usage metering for the Cloud Console — the billing foundation.

Increments per-tenant, per-month counters (events ingested, API calls). A future
billing integration reads `UsageCounter`; nothing here talks to a payment
provider, so it stays metadata-only and dependency-free.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from secureagentnet.cloud import models


def current_period() -> str:
    """Billing period key, e.g. '2026-07'."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


def record_usage(session, tenant_id, *, events: int = 0, api_calls: int = 0) -> None:
    """Upsert this tenant's counter for the current period. Best-effort: metering
    must never break the request path, so callers may wrap in try/except."""
    if not tenant_id or (events == 0 and api_calls == 0):
        return
    period = current_period()
    counter = session.execute(
        select(models.UsageCounter).where(
            models.UsageCounter.tenant_id == tenant_id,
            models.UsageCounter.period == period,
        )
    ).scalar_one_or_none()
    if counter is None:
        counter = models.UsageCounter(tenant_id=tenant_id, period=period,
                                      events_ingested=0, api_calls=0)
        session.add(counter)
    counter.events_ingested += events
    counter.api_calls += api_calls
    counter.updated_at = datetime.now(timezone.utc)
