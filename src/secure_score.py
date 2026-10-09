"""Selection helpers for time ordered Microsoft Secure Score snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def latest_secure_score(scores: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Return the newest snapshot only when its ordering is verifiable.

    A single record is unambiguous even if the API omitted its timestamp.
    Multiple records require a valid createdDateTime on every row. If any
    timestamp is absent or malformed, report no verified latest snapshot.
    """
    if not scores:
        return None
    if len(scores) == 1:
        return scores[0]

    dated: list[tuple[datetime, dict[str, Any]]] = []
    for row in scores:
        value = row.get("createdDateTime")
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        dated.append((parsed.astimezone(timezone.utc), row))
    return max(dated, key=lambda item: item[0])[1]
