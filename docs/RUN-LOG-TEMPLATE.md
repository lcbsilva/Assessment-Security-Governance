# Registro de execução interna

Copie este modelo para cada execução. Não inclua tokens, UPNs, nomes de pessoas ou dados brutos do tenant.

```yaml
run_id: ""
date_utc: ""
engine_version: ""
schema_version: ""
profile: "full"
tenant_label: "interno-mascarado"
subscriptions_count: 0
users_assessed: 0
resources_assessed: 0
duration_minutes: 0
resumed: false
checkpoints_reused: []
execution_health: ""
evidence_quality_score: 0
status_counts:
  success: 0
  partial: 0
  not_available: 0
  error: 0
throttling_observed: false
modules_with_error: []
portal_cross_check:
  azure_resource_graph: "pending"
  entra: "pending"
  defender: "not_applicable"
  cost_management: "pending"
consultant_friction:
  authentication: ""
  execution: ""
  report_review: ""
false_positives: []
false_negatives: []
defects_opened: []
decision: "repeat|fix|accept_limitation|ready_for_next_run"
notes: ""
```
