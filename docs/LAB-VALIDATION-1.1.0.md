# Azure Lab validation — 1.1.0

Real authorized lab execution completed for the security, governance and full profiles against the approved lab subscription.

Observed acceptance signals: tenant/subscription safety gate passed; readiness completed without blocking checks; contracts were valid; artifact validation and manifests were valid; pilot validation reached `ready_for_pilot_review`; Delivery Gate reached `ready_for_client_review` for all three profiles; execution remained read-only.

Observed collector limitation: Microsoft Graph completed as `partial` and dominated elapsed collection time (~103–116 seconds). Optional Azure DevOps and M365 modules remained `not_available` in the full profile because their optional configuration/coverage was unavailable. These states remain limitations, not compliance claims.

Sprint 17 therefore reduces the default per-request Graph timeout from 60s to 30s and the default sign-in page cap from 20 to 10. Both remain operator-overridable. A capped sign-in collection is already recorded as `partial`, preserving evidence semantics instead of silently claiming full coverage.
