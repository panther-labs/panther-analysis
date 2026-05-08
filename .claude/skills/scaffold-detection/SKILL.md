---
name: scaffold-detection
description: >-
  Scaffold a new Panther detection (rule, policy, or scheduled rule) end to end:
  pick the right directory and paradigm, copy from templates/, ground field
  names in the real log schema, generate matching RuleID/Filename/DisplayName,
  write redacted positive+negative unit tests, add MITRE mapping, and verify
  with a scoped `pat test`. Use when the user asks to "create / write / add /
  scaffold a (new) Panther rule / detection / policy / signal" for a specific
  log type, log source, or behavior — especially for log sources or behaviors
  not already covered in the repo. Do NOT use for editing or tuning existing
  detections; for that, just edit the file directly.
---

# Scaffold a new Panther detection

End-to-end workflow for adding a new detection to `panther-analysis`. The conventions, metadata schema, and gotchas live in [`AGENTS.md`](../../../AGENTS.md) — this skill is the *procedure* that applies them. Read AGENTS.md §1 (Critical rules), §4 (Writing detections), and §7 (Stateful detections) before scaffolding anything non-trivial.

## Step 0 — Clarify before scaffolding

Don't start writing files until you can answer all four. Ask the user if any are unclear:

1. **Log type** (exact Panther name, e.g. `AWS.CloudTrail`, `Okta.SystemLog`, `GCP.AuditLog`).
2. **Behavior to detect** in one sentence. ("Alert when an IAM role is assumed from an IP outside our allowlist.")
3. **Paradigm:** Python rule, Simple Detection (YAML-only), policy, scheduled rule, signal, or correlation rule. Default to Python rule unless the logic is purely declarative field comparisons (use Simple Detection) or it's stateless audit labeling (signal). See AGENTS.md §5 and §6.
4. **Severity** and rough alert volume expectation. Affects `Severity:`, `DedupPeriodMinutes:`, and whether to use `Threshold` + `unique()` (AGENTS.md §7.1).

## Step 1 — Ground in real data (use the Panther MCP if available)

Tools prefixed `mcp__panther-…__` come from the Panther MCP server (see AGENTS.md §11). If they're not available, fall back to the Panther docs and ask the user for sample logs.

1. **Schema first.** `get_log_type_schema_details` for the target log type. Confirm exact field paths (`userIdentity.arn`, not `user_identity.arn`) and casing — these will go into `event.deep_get(...)` calls.
2. **Sample real events.** `query_data_lake` with a tight `LIMIT` (e.g. 5–10) to pull representative rows that *would* trigger the rule. Add `p_event_time` predicates to keep the query cheap.
3. **Check for prior art.** `list_detections --filter LogTypes=<LogType>` and `list_global_helpers` so you don't duplicate an existing rule or re-implement a helper. If a similar rule exists, ask the user whether to extend it instead.

**Hard rule:** anything pulled from `query_data_lake` is real customer data. **Redact every account ID, email, IP, hostname, and identifier before it enters a YAML test, commit, or message.** Use `123456789012` for AWS account IDs, `192.0.2.x` for IPs, `user@example.com` for emails. See AGENTS.md §1.1.

## Step 2 — Pick the directory

Detections live alongside their log source family:

| Paradigm | Directory pattern | Examples |
| --- | --- | --- |
| Rule | `rules/<logsource>_rules/` | `rules/aws_cloudtrail_rules/`, `rules/okta_rules/`, `rules/gsuite_activityevent_rules/` |
| Policy | `policies/<service>_policies/` | `policies/aws_iam_policies/`, `policies/aws_s3_policies/` |
| Scheduled rule | `rules/<logsource>_rules/` (paired with a query in `queries/`) | `rules/snowflake_rules/` |
| Correlation rule | `correlation_rules/` (subrules/signals stay in their log-source dir) | see AGENTS.md §10 |

If a directory for the log source doesn't exist yet, create it. Use `ls rules/` to find the closest existing convention and match the naming.

## Step 3 — Generate the file pair

Always copy from `templates/`, never write from a blank file:

- Python rule:        `templates/example_rule.py`        + `templates/example_rule.yml`
- Policy:             `templates/example_policy.py`      + `templates/example_policy.yml`
- Scheduled rule:     `templates/example_scheduled_rule.py` + `.yml` + `templates/example_scheduled_query.yml`

### Generate the naming triplet

The `RuleID`, `Filename`, and `DisplayName` must be recognizably the same detection (AGENTS.md §4.3). Pick the `RuleID` first, then derive the other two:

- `RuleID`: `<LogFamily>.<Source>.<DetectionName>` in PascalCase — e.g. `AWS.CloudTrail.IAMCompromisedKeyQuarantine`
- `Filename`: snake_case version of the RuleID's tail — e.g. `aws_iam_compromised_key_quarantine.py`
- `DisplayName`: human-readable Title Case — e.g. `"AWS Compromised IAM Key Quarantine"`

`Filename:` in the YAML must exactly match the `.py` filename or `pat test` fails with a confusing error.

## Step 4 — Write the rule logic

Apply the patterns from AGENTS.md §4.5:

- **Always `event.get("field", default)` / `event.deep_get("a", "b", default=...)`.** Never `event["field"]`.
- **Don't import `deep_get` from `panther_base_helpers`** — it's a method on `event`.
- **Order conditions by selectivity** (most restrictive first) for short-circuit performance.
- **Reuse `alert_context` helpers** before writing one — check `global_helpers/` for one matching the log family (`aws_rule_context`, `okta_alert_context`, etc.) and extend with `|`:
  ```python
  return aws_rule_context(event) | {"extra_field": event.get("extra_field", "")}
  ```
- **For "N distinct X within window" detections, use `unique()` + `Threshold:` instead of a DynamoDB cache.** See AGENTS.md §7.1 for the pattern and in-repo examples.
- For Simple Detections, use the match-expression grammar in AGENTS.md §5 — no `.py` file at all.

## Step 5 — Fill the YAML metadata

Required fields (AGENTS.md §4.2): `AnalysisType`, `Filename`, `RuleID`, `DisplayName`, `Enabled`, `LogTypes`, `Severity`, plus `Description`, `Runbook`, `Reference`.

- **`Reference`:** must link to threat research or a security writeup — *not* a generic API/log-source doc page.
- **`Runbook`:** concrete triage steps for an on-call responder.
- **`Reports.MITRE ATT&CK`:** format `TA####:T####` or `TA####:T####.###`, with the technique name as a comment on the same line. Optionally add the technique name to `Tags:` too:
  ```yaml
  Reports:
    MITRE ATT&CK:
      - TA0006:T1556  # Modify Authentication Process
  Tags:
    - Modify Authentication Process
  ```
- **`DedupPeriodMinutes`:** see AGENTS.md §9 dedup window table — default 60, drop to 15 for high-frequency, raise to 720+ for rare events.
- **`Severity`:** title case in YAML (`High`, not `HIGH`).

## Step 6 — Write unit tests (positive AND negative)

Place the `Tests:` block at the very bottom of the YAML. Minimum two test cases:

- One `ExpectedResult: true` case — the canonical positive trigger.
- One `ExpectedResult: false` case — the obvious near-miss that should *not* fire (right log type, wrong field value).

Pull the test log shapes from the real samples gathered in Step 1, **then redact every identifier** before saving. If the rule uses cache helpers (rare — prefer `unique()`), add a `Mocks:` block (AGENTS.md §8.2). If you're not using `unique()` but the rule logic depends on threshold semantics, also include an edge-case test for an event missing the key fields entirely.

## Step 7 — Verify locally

Run scoped tests, not the full suite:

```bash
pipenv run panther_analysis_tool test --filter RuleID=<NewRuleID>
```

If the rule needs deeper iteration, `pipenv run pat debug <RuleID> "<test name>"` lets you set breakpoints and use prints.

Once the rule's own tests pass, run the full pre-PR trio:

```bash
make fmt && make lint && make test
```

Don't disable lints to make CI green — fix the underlying issue (AGENTS.md §1.4).

## Step 8 — Pack assignment (optional but appreciated)

If the log source has a pack in `packs/`, add the new `RuleID` to it. For correlation rules, follow AGENTS.md §10 — single-LogType CRs go in that LogType's pack along with their subrules.

## Step 9 — Hand back to the user

Summarize for the user:
- The two new file paths (`.py` and `.yml`).
- The chosen `RuleID`, paradigm, severity, and dedup window with a one-line justification.
- Test results from Step 7.
- Anything you couldn't decide and need confirmation on (severity calls, MITRE mapping ambiguity, whether to extend an existing rule instead).

Remind them to open the PR against `develop`, not `main` (AGENTS.md §1.2): `gh pr create --base develop ...`.

## Things this skill should NOT do

- Don't author correlation rules with this skill — they have a separate flow that requires `pat validate` against a live instance. See AGENTS.md §10.
- Don't tune or refactor existing detections. Edit the file directly.
- Don't paste un-redacted MCP query results into any file or message.
- Don't push, open a PR, or merge without the user explicitly asking — scaffolding ends at the local file pair plus passing tests.
