# Implementation Notes

## Azure Monitor Logs Query API

The Log Analytics API should be used through a backend service, not directly from an untrusted frontend.

Recommended endpoint shape:

```http
POST https://api.loganalytics.azure.com/v1/workspaces/{workspaceId}/query
```

Recommended request body:

```json
{
  "query": "SigninLogs | where TimeGenerated >= ago(1d) | count",
  "timespan": "P1D"
}
```

Recommended headers:

```http
Authorization: Bearer <token>
Content-Type: application/json
Prefer: include-statistics=true
Prefer: include-dataSources=true
Prefer: wait=300
```

## Authentication and Permissions

Use Microsoft Entra authentication. The implementation may use delegated user auth or an application/service principal.

Minimum access should be based on least privilege:

- Read access for Log Analytics query execution.
- Sentinel contributor level access only if deployment is supported.
- Separate read-only and deploy-capable modes where possible.

Never ask the model to handle client secrets directly.

## Query Safety Controls

Before a query is sent to Log Analytics:

- Require an explicit timespan.
- Block or require approval for broad `union *` and `search *` patterns.
- Prefer `count`, `summarize`, `getschema`, and `take` for validation.
- Cap samples.
- Avoid returning raw sensitive values by default.
- Log the purpose of every query.

## Performance Review

Request statistics when executing performance checks.

The model should assess:

- Query duration.
- Table volume.
- Operators likely to increase cost.
- Joins before filtering.
- Regex and contains usage.
- Excessive dynamic parsing.
- High-cardinality summarize operations.
- Whether the rule is suitable for scheduled execution.

## Sentinel Deployment

The assistant may draft a Sentinel scheduled analytics rule. It must not deploy or modify rules without explicit user approval.

Recommended deployment flow:

1. Analyse or create detection.
2. Present recommended rule metadata and KQL.
3. User approves deployment.
4. Backend deploys via Sentinel API.
5. Backend returns deployment result and rule ID.

## Suggested Folder Integration

A simple project structure could look like:

```text
src/
  prompts/
    kql_analyser_system_prompt.md
  tools/
    log_analytics_client.ts
    sentinel_client.ts
  schemas/
    analyser_report.schema.json
  services/
    query_safety.ts
    detection_analyser.ts
    report_renderer.ts
```

## Recommended UX

Inputs:

- Detection intent.
- Existing KQL or create-new mode.
- Workspace selector.
- Timespan.
- Query frequency and period.
- Allow query execution toggle.
- Allow raw examples toggle.

Outputs:

- Verdict.
- Score.
- Issues.
- Performance review.
- Recommended KQL.
- Sentinel rule configuration.
- Validation queries.
- JSON report export.
