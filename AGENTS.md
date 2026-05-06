# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, etc.) working in `panther-analysis`. Human contributors should also find this useful — it consolidates the rules, conventions, and gotchas that keep the repo healthy.

This is the canonical source. Tool-specific entrypoints (`CLAUDE.md`, `.cursorrules`, etc.) should reference this file rather than duplicate its contents.

---

## 1. Critical rules — read before doing anything

These are non-negotiable. Violating them creates security, legal, or release-process problems.

### 1.1 This is a PUBLIC repository
- **Never commit customer data, customer names, internal hostnames, real user emails, real IPs, real account IDs, API keys, tokens, or any other sensitive information.**
- Sample logs in unit tests **must be redacted/synthesized**. Use placeholder values like `123456789012` for AWS account IDs, `user@example.com` for emails, `192.0.2.x` (TEST-NET-1) for IPs.
- If you're adapting a real-world detection from an incident, scrub identifiers and rephrase any specifics that could fingerprint the source.
- Internal Panther context (Jira tickets, Slack threads, customer specifics) belongs in PR descriptions or commits **only if** it does not leak protected information — when in doubt, leave it out.

### 1.2 All PRs target `develop`, not `main`
- The default working branch is `develop`. `main` is the released branch and is updated by Panther's release process.
- When opening a PR with `gh pr create`, pass `--base develop` explicitly. Do **not** rely on the GitHub default.
- Do not push directly to `develop` or `main`. Always go through a PR.

### 1.3 CLA required
- All external contributors must sign the [Contributor License Agreement](https://gist.githubusercontent.com/jacknagz/5d097acd8c6ea462361e2d375b87e519/raw/21d2f529bf52c07e7e5c7be8acfe2f7d66688eae/Panther-Labs-CLA.txt) before a PR can merge. CI will block unsigned contributions.

### 1.4 Don't disable, skip, or weaken tests/linters to "make CI green"
- If `make lint` or `make test` fails, fix the underlying issue. Do not add `# pylint: disable=...`, delete failing tests, or use `--no-verify` on commits to bypass hooks.

---

## 2. Repository at a glance

| Path | Purpose |
| --- | --- |
| `rules/` | Streaming detection rules (analyze logs in real time) |
| `policies/` | Cloud resource configuration / compliance checks |
| `queries/` | Scheduled queries and signals for threat hunting |
| `correlation_rules/` | Multi-step / multi-signal attack patterns |
| `data_models/` | Field normalization across log sources (UDM-style) |
| `global_helpers/` | Reusable Python utilities (per-platform: `panther_aws_helpers`, `panther_okta_helpers`, etc.) |
| `lookup_tables/` | Reference data (CIDR ranges, account allowlists, etc.) |
| `packs/` | YAML manifests grouping detections for deployment |
| `templates/` | Starter templates for new detections — copy from here |
| `style_guides/` | Detailed style guides (read these) |
| `indexes/` | Auto-generated indexes — do not hand-edit |
| `deprecated.txt` | Tracks deleted detection IDs for customer cleanup |

### Dual-file architecture
Every detection is **two files** with the same basename:
- `foo_bar.py` — Python detection logic
- `foo_bar.yml` — metadata, configuration, and unit tests

The `.yml` `Filename:` field must match the `.py` filename exactly. Both files must be committed together.

---

## 3. Local development workflow

### Setup
```bash
make install                    # pipenv sync --dev
make install-pre-commit-hooks   # one-time
pipenv shell                    # activate venv
```

### The "before pushing" trio
Always run all three locally before opening a PR. CI runs the same checks.
```bash
make fmt    # isort + black (line length 100)
make lint   # pylint + bandit + isort check + black check
make test   # global helper unit tests + data model unit tests + pat test
```

### `panther_analysis_tool` (pat) — the workhorse
`pat` is the CLI used to test, validate, and upload detections. Always invoke through pipenv.

| Task | Command |
| --- | --- |
| Run all detection tests | `pipenv run panther_analysis_tool test` |
| Test one directory | `pipenv run panther_analysis_tool test --path rules/aws_cloudtrail_rules/` |
| Test one rule by ID | `pipenv run panther_analysis_tool test --filter RuleID=AWS.CloudTrail.Example` |
| Run a single named test case | `pipenv run pat test --filter RuleID=<id> --test-names "Specific test name"` |
| Filter by severity | `pipenv run pat test --filter Severity=CRITICAL` (comma-separate for multiple: `High,Critical`) |
| Filter by log type | `pipenv run pat test --filter LogTypes=AWS.GuardDuty` |
| Filter by analysis type | `pipenv run pat test --filter AnalysisType=rule` (or `policy`, or `rule,policy`) |
| Enforce minimum coverage | `pipenv run pat test --minimum-tests 2` (requires both a true and false case) |
| Debug a single test (print/breakpoints work) | `pipenv run pat debug <RuleID> "<unit test name>"` |
| Validate against a live instance (required for correlation rules) | `pipenv run pat validate --api-token ... --api-host ...` |
| Build zip of detections | `pipenv run pat zip` |
| Upload to a Panther instance | `pipenv run pat upload --api-token ... --api-host ...` |

> Files cannot be passed as test arguments — only metadata attributes (`RuleID`, `LogTypes`, etc.).

**Gotchas:**
- `pat test` runs unit tests defined in the `.yml` `Tests:` block. It does **not** make network calls and does not validate against a live Panther instance.
- **Correlation rules cannot be fully tested with `pat test`.** Use `pat validate` against a Panther instance — see [`style_guides/CORRELATION_RULES_STYLE_GUIDE.md`](style_guides/CORRELATION_RULES_STYLE_GUIDE.md).
- When iterating on a single rule, **always** scope with `--path` or `--filter`. The full test suite is large.
- `make test` already wraps `pat test` plus the helper/data-model unit tests — prefer it as the final gate.

### Docker alternative
If local `pipenv` is broken, `make docker-build && make docker-test` runs everything in a container.

---

## 4. Writing detections

### 4.1 Start from a template
Don't write from scratch. Copy the appropriate file from `templates/`:
- `templates/example_rule.py` + `example_rule.yml`
- `templates/example_policy.py` + `example_policy.yml`
- `templates/example_scheduled_rule.py` + `example_scheduled_rule.yml`

### 4.2 Required YAML metadata
| Field | Notes |
| --- | --- |
| `AnalysisType` | `rule`, `policy`, `scheduled_rule`, `scheduled_query`, or `correlation_rule` |
| `Filename` | Must exactly match the `.py` filename |
| `RuleID` / `PolicyID` | Format: `LogFamily.LogType.DetectionName` (e.g. `AWS.CloudTrail.IAMCompromisedKeyQuarantine`). Globally unique. |
| `DisplayName` | Human-readable, title case |
| `Enabled` | Boolean |
| `LogTypes` (rules) / `ResourceTypes` (policies) | List |
| `Severity` | `Info`, `Low`, `Medium`, `High`, or `Critical` — see [Alert Severity Guidelines](https://docs.panther.com/detections/rules#alert-severity) |
| `Description`, `Runbook`, `Reference` | Strongly recommended; `Reference` should link to threat research, not generic API docs |
| `Tests` | Always at the bottom of the file; include positive AND negative cases |

### 4.3 Naming consistency rule
`RuleID`, `Filename`, and `DisplayName` must be recognizably the same detection. Litmus test: given the `RuleID`, a reader should be able to guess the filename, and vice versa.

```yaml
DisplayName: "AWS Compromised IAM Key Quarantine"
RuleID:      "AWS.CloudTrail.IAMCompromisedKeyQuarantine"
Filename:    aws_iam_compromised_key_quarantine.py
```

### 4.4 MITRE ATT&CK mapping format
```yaml
Reports:
  MITRE ATT&CK:
    - TA0006:T1556        # Modify Authentication Process
    - TA0006:T1556.006    # subtechnique format: TA####:T####.###
Tags:
  - Modify Authentication Process
```
A comment with the technique name on the same line is required. `make lint-mitre` validates the mapping.

### 4.5 Python patterns

**Use safe field access. Never use `event['field']`.**
```python
# Good
event.get("field", "")
event.deep_get("nested", "field", default="")

# Bad — raises AttributeError when fields are missing
event["field"]
event["nested"]["field"]
```

`deep_get` is built into Panther's normalized event class. **Don't import it from `panther_base_helpers`** — call it as a method on `event`.

**Always specify a default** in `get`/`deep_get` to defend against missing fields.

**Reuse existing `alert_context` helpers** — check `global_helpers/` for one matching your log type before writing a new one. Extend rather than replace:
```python
from panther_aws_helpers import aws_rule_context

def alert_context(event):
    return aws_rule_context(event) | {"another_field": event.get("another_field", "")}
```

**Use dynamic functions** (`title`, `severity`, `dedup`, `description`, `reference`, `runbook`, `destinations`) when the alert should adapt to event content. See `templates/example_rule.py` for the full surface.

### 4.6 Unit tests (`Tests:` block)
- Include **both** a positive case (`ExpectedResult: true`) and a negative case (`ExpectedResult: false`).
- Cover edge cases: missing fields, empty values, malformed input.
- Use realistic but **fully redacted** sample logs — see §1.1.
- Place the `Tests:` block at the very bottom of the `.yml` file.
- Add a `Mocks:` block when the detection calls helpers that hit external state.

### 4.7 Code style
- Python 3.11.
- Black, line length **100**.
- isort with `--profile=black`.
- Pylint and bandit must pass.
- Type hints encouraged but not required for trivial detections.
- Keep comments minimal — explain *why*, not *what*. Well-named functions and clear logic beat narrative comments.

---

## 5. Simple Detections (YAML-only rules)

Panther also supports a YAML-only "Simple Detection" paradigm. Instead of a Python `rule()`, the `.yml` file contains a `Detection:` block of declarative match expressions — no `.py` file at all. Use this when the logic is purely a set of field comparisons; reach for Python when you need branching, lookups, or stateful caching.

### Example
```yaml
AnalysisType: rule
RuleID: AWS.RootAccount.PublicIPUsage
Enabled: true
LogTypes: [AWS.CloudTrail]
Severity: High
Detection:
  - KeyPath: userIdentity.type
    Condition: Equals
    Value: Root
  - KeyPath: sourceIPAddress
    Condition: IsIPAddressPublic
  - KeyPath: errorCode
    Condition: IsNull
AlertTitle: "Root account [{userIdentity.accountId}] used from public IP [{sourceIPAddress}]"
GroupBy:
  - KeyPath: sourceIPAddress
DedupPeriodMinutes: 60
Tests:
  - Name: Public IP root usage
    ExpectedResult: true
    Log: { ... }
```

### Key specifiers
- `KeyPath: foo` — top-level field
- `KeyPath: foo.bar.baz` — dot notation for nested fields
- `KeyPath: foo[*].bar` — wildcard array access
- `KeyPath: foo.bar[2]` — specific index
- `DeepKey: [foo, bar, baz]` — list form (use `KeyPath` for consistency)

### Match expression types
1. **Key/Value** — `KeyPath` + `Condition` + `Value`
2. **Key/Values** — `KeyPath` + `Condition: IsIn` + `Values: [...]`
3. **Multi-key** — compare two fields: `Condition: IsGreaterThan` + `Values: [{KeyPath: a}, {KeyPath: b}]`
4. **List comprehension** — `Condition: AnyElement` / `AllElements` / `OnlyOneElement` / `NoElement` + nested `Expressions:`
5. **Existence** — `Condition: Exists` / `DoesNotExist` / `IsNull` / `IsNotNull` / `IsNullOrEmpty`
6. **Absolute** — `Condition: AlwaysTrue` / `AlwaysFalse`

### Common conditions
- Equality: `Equals`, `DoesNotEqual`, `IEquals` (case-insensitive variants prefix `I`)
- String: `StartsWith`, `EndsWith`, `Contains` (+ `DoesNot…` and `I…` variants)
- Numeric: `IsGreaterThan`, `IsGreaterThanOrEqual`, `IsLessThan`, `IsLessThanOrEqual`
- IP address: `IsIPAddress`, `IsIPv4Address`, `IsIPv6Address`, `IsIPAddressPublic`, `IsIPAddressPrivate`, `IsIPAddressInCIDR`
- List membership: `IsIn`, `IsNotIn` (with `Values:`)

### Combinators
Default is `All` (AND). Explicit forms:
```yaml
Detection:
  - Any:        # OR
      - {KeyPath: eventName, Condition: StartsWith, Value: List}
      - {KeyPath: eventName, Condition: StartsWith, Value: Describe}
  - All: [...]  # AND (explicit)
  - OnlyOne: [...]  # XOR
  - None: [...]     # NOT AND
```

### Inline filters
The same match-expression grammar drives `InlineFilters:` on Python rules — use it to filter events out before the Python `rule()` runs. Inline filters support a slightly reduced condition set (no list comprehension; see [Panther docs](https://docs.panther.com/detections/rules/inline-filters)).

### Simple Detection-only fields
- `Detection:` — the match-expression block (replaces `rule()`)
- `AlertTitle:` — title template with `{field}` interpolation (replaces `title()`)
- `AlertContext:` — list of key/value pairs to attach (replaces `alert_context()`)
- `GroupBy:` — list of `KeyPath`s used for dedup (replaces `dedup()`)
- `DynamicSeverities:` — list of `{ChangeTo, Conditions}` blocks (replaces `severity()`)

---

## 6. Signals (rules that don't alert)

A "signal" is a rule that labels matching events with its `RuleID` but does not generate an alert. Useful for security-relevant audit events that other rules or correlation rules consume.

```yaml
AnalysisType: rule
RuleID: Panther.LoginSignal
LogTypes: [Panther.Audit]
Severity: Info
CreateAlert: false   # <-- the key flag
Enabled: true
```
Conventions:
- `CreateAlert: false`
- `Severity: Info`
- For Python signals: only define `rule()` — skip `title`, `dedup`, `alert_context`, etc.
- Skip alert-related metadata (`DedupPeriodMinutes`, `Threshold`, `Runbook`).
- Reuse existing signals before creating new ones (especially for correlation rule subrules).

---

## 7. Stateful detections

Most "alert when N distinct X within a window" detections do **not** need a manual cache. Use the built-in [unique-value thresholding](https://docs.panther.com/detections/rules#unique-value-thresholding) feature first, and reach for the DynamoDB cache only when state must persist beyond a single dedup window or the logic isn't expressible as "count distinct values."

### 7.1 Unique-value thresholding — preferred for "N distinct X" rules

Add a `unique(event) -> str` function to a Python rule. Panther applies the YAML `Threshold:` to the **estimated count of distinct values returned by `unique()`** within each `DedupPeriodMinutes` window, instead of the raw event count. The unique counter resets at the end of every dedup window automatically — no TTLs, no DynamoDB calls, no mocks.

Use it when you'd otherwise be tempted to write "track seen values in a string set":
- "5+ unique source IPs hitting the same user" → `unique()` returns `sourceIPAddress`, `Threshold: 5`, `dedup()` returns the username
- "Same MFA phone enrolled by multiple users" → `unique()` returns `user_id`, `dedup()` returns the phone number
- "User accessing many distinct workspaces" → `unique()` returns the workspace ID, `dedup()` returns the actor

```python
# rules/auth0_rules/auth0_same_phone_mfa_multiple_users.py — abbreviated
def rule(event):
    return (
        event.deep_get("data", "type") == "gd_enrollment_complete"
        and event.deep_get("data", "description") == "Guardian - Enrollment complete (sms)"
        and bool(event.deep_get("data", "details", "authenticator", "phone_number"))
    )

def unique(event):
    return event.deep_get("data", "user_id", default="")

def dedup(event):
    return str(event.deep_get("data", "details", "authenticator", "phone_number", default=""))
```
With `Threshold: 2` in the YAML, this fires when ≥2 distinct `user_id`s enroll the same phone within `DedupPeriodMinutes`.

**Rules of thumb:**
- `unique()` returns the field whose **cardinality** you're thresholding.
- `dedup()` (or `GroupBy:`) returns the field that **groups** the alert — what stays constant.
- The standard `Threshold:` field now means "distinct unique-values," not raw event count.
- Counts are an *estimate* (HyperLogLog-style) — fine for "≥ N" detections, not for exact accounting.
- Minimum `DedupPeriodMinutes` is 5 (API/CLI) or 15 (Console UI); the unique counter resets each window.
- Existing examples in the repo: [`auth0_same_phone_mfa_multiple_users.py`](rules/auth0_rules/auth0_same_phone_mfa_multiple_users.py), [`databricks_access_to_multiple_workspaces.py`](rules/databricks_rules/databricks_access_to_multiple_workspaces.py), [`k8s_secret_enumeration.py`](rules/kubernetes_rules/k8s_secret_enumeration.py), [`snowflake_stream_password_spray.py`](rules/snowflake_rules/snowflake_stream_password_spray.py).
- `unique()` is **Python-only** — Simple Detections cannot use it.
- `unique()` works in `pat test` without mocks; no cache stub required.

### 7.2 DynamoDB cache — when `unique()` is not enough

Use the manual cache only for state that `unique()` cannot express:
- Persistence beyond a single dedup window (e.g. "first time we've **ever** seen this value").
- Counters with custom reset logic or arithmetic.
- Cross-rule shared state.
- Storing structured values (not just distinct-value counts).

**Caching only works in the Panther Console — local `pat test` requires mocked cache calls (see §8.2).** Helpers live in `panther_detection_helpers.caching`.

#### String sets
```python
from panther_detection_helpers.caching import add_to_string_set, get_string_set

def rule(event):
    if event.get("eventName") != "AssumeRole":
        return False
    role_arn = event.deep_get("requestParameters", "roleArn")
    if not role_arn:
        return False
    key = f"{role_arn}-UniqueSourceIPs"
    ip = event.get("sourceIPAddress", "")
    seen = get_string_set(key)
    if not seen:
        add_to_string_set(key, ip, epoch_seconds=event.event_time_epoch() + 7 * 24 * 3600)
        return False
    return ip not in seen
```
APIs: `get_string_set`, `put_string_set`, `add_to_string_set`, `remove_from_string_set`, `reset_string_set`.

> Note: this exact "alert on a never-before-seen IP" pattern is **not** a `unique()` use case (`unique()` resets per window; here we want indefinite memory).

#### Counters
```python
from panther_detection_helpers.caching import increment_counter, set_key_expiration, reset_counter

def rule(event):
    if event.get("errorCode") != "AccessDenied":
        return False
    key = f"{event.deep_get('userIdentity', 'arn')}-AccessDeniedCounter"
    count = increment_counter(key)
    if count == 1:
        set_key_expiration(key, event.event_time_epoch() + 3600)
    if count >= 10:
        reset_counter(key)
        return True
    return False
```
APIs: `get_counter`, `increment_counter`, `reset_counter`, `set_key_expiration`.

> Note: a plain "≥10 access-denied events from the same ARN per hour" rule should usually use `Threshold: 10` + `DedupPeriodMinutes: 60` + `GroupBy: userIdentity.arn` — no cache needed. Reach for `increment_counter` only when you need custom reset behavior.

#### TTL gotchas
- Default TTL is **90 days** — don't rely on it; set explicit expirations.
- **Use `event.event_time_epoch()` for TTL math, not `time.time()`** — replayed or delayed events would otherwise expire incorrectly.
- Don't put timestamps in cache **keys** — they break reproducibility.

#### Pitfalls
- Reaching for the cache when `Threshold` + `unique()` would do the job.
- Calling cache APIs before checking event relevance — wastes latency.
- Adding to a string set before checking for the value already being present — corrupts the dedup logic.
- Forgetting TTL — leads to unbounded cache growth.
- Forgetting to mock cache calls in unit tests (see §8.2).

---

## 8. Unit tests — additional patterns

### 8.1 Test coverage policy
When `--minimum-tests 2` (or higher) is enforced, every detection must have:
- ≥ N tests
- ≥ 1 test that returns `true`
- ≥ 1 test that returns `false`

### 8.2 Mocking helpers and cache
Use the `Mocks:` block to stub out cache calls or external helpers in unit tests:
```yaml
Tests:
  - Name: Hits the threshold
    ExpectedResult: true
    Mocks:
      - objectName: get_counter
        returnValue: 10
      - objectName: increment_counter
        returnValue: 11
    Log: { ... }
```

### 8.3 Sample log realism
Use real-looking field shapes from actual log schemas — but **fully redact** identifiers (§1.1). Use `123456789012` for AWS account IDs, `192.0.2.x` for IPs, `user@example.com` for emails.

---

## 9. Runtime environment

The Python detection runtime ships with a small set of third-party libraries pre-installed:
- `jsonpath-ng` — JSONPath queries
- `policyuniverse` — AWS ARN and IAM policy parsing
- `requests` — HTTP

Don't add new runtime dependencies casually — they require platform changes.

### Useful event methods (beyond `get`/`deep_get`)
- `event.deep_walk("a", "b", "c")` — walks through arrays of dicts, returning a flattened list of values at the leaf path. Useful when intermediate nodes are lists.
- `event.event_time_epoch()` — the event's normalized timestamp in epoch seconds. Use this for cache TTLs.
- `p_*` fields — Panther-added metadata (e.g. `p_log_type`, `p_event_time`). `p_any_*` fields contain extracted indicators (IPs, domains, etc.).

### Performance-oriented patterns
- Order conditions in `rule()` by selectivity (most restrictive first) to leverage Python short-circuiting.
- Return early — exit `rule()` as soon as a precondition fails.
- Don't implement thresholds in Python; use the `Threshold:` YAML field. Panther aggregates.
- Don't make `title()` so unique that it fragments alerts — dedup depends on it.

### Dedup window guidelines
| Window | When to use |
| --- | --- |
| 15 min | High-frequency events (login failures, API errors) |
| 60 min | Standard security events (privilege changes, data access) — **default** |
| 180 min | Compliance-style events |
| 720 min | Low-frequency events (account creation) |
| 1440 min | Rare events (root account usage) |

---

## 10. Correlation rules — extra rules

Read [`style_guides/CORRELATION_RULES_STYLE_GUIDE.md`](style_guides/CORRELATION_RULES_STYLE_GUIDE.md). Highlights:

- Files live in `correlation_rules/`. Subrules and signals go in the appropriate logtype directory (e.g. `rules/aws_cloudtrail_rules/`).
- **Test with `pat validate`** against a live Panther instance — `pat test` cannot fully exercise correlation logic.
- Reuse existing signal rules (e.g. `AWS Console Login`); don't duplicate.
- Sequence/group/transition IDs should be meaningful (`GHASChange`, not `TR.1`).
- When writing transition descriptions inside an ID, capitalize the verb: `"GitHub Advanced Security Change NOT FOLLOWED BY repo archived"`.
- Strip boilerplate UI-template comments (e.g. `# Create a list of rules to correlate`) before committing.
- `MinMatchCount: 1` is the default — omit it. `LookbackWindowMinutes` should be ≥ 1.5× `RateMinutes`.
- `Match On` fields must be scalar; for cross-LogType matches, project transformed values into `p_alert_context` from each subrule.

---

## 11. Panther MCP server — live-instance tooling

The [Panther MCP server](https://github.com/panther-labs/mcp-panther) ([docs](https://docs.panther.com/panther-developer-workflows/mcp-server)) exposes a Panther deployment as an MCP toolset to AI clients (Claude Code, Cursor, Claude Desktop, Goose). When configured, agents can query the data lake, inspect schemas, list/get detections, look up alerts, and read global helpers from a real Panther instance — turning detection authoring from "write blindly against docs" into "ground every choice in actual data."

If your client already has Panther MCP tools available (look for tool names prefixed with `mcp__panther-…__`), prefer them over guessing field names or fabricating sample logs.

### 11.1 When to reach for it during detection work

| Situation | MCP tool(s) |
| --- | --- |
| "What fields exist on log type X?" — before writing `event.deep_get(...)` | `get_log_type_schema_details`, `list_log_type_schemas` |
| "Show me a real event for this log type" — for realistic test cases (then redact!) | `query_data_lake` |
| "What table/column do I query in the data lake?" | `list_databases`, `list_database_tables`, `get_table_schema` |
| Check whether a similar detection already exists | `list_detections`, `get_detection` |
| Reuse an existing helper instead of writing a new one | `list_global_helpers`, `get_global_helper` |
| Validate a scheduled-query rule against real data | `query_data_lake`, `get_scheduled_query` |
| Confirm a data model normalization | `list_data_models`, `get_data_model` |
| Investigate an alert that motivated the detection | `get_alert`, `get_alert_events`, `summarize_alert_events` |
| Triage existing alert volume / FP rate before tuning severity | `list_alerts`, `get_rule_alert_metrics`, `get_severity_alert_metrics` |

### 11.2 The "ground in real data" loop

A good MCP-augmented authoring flow:
1. **Schema first.** `get_log_type_schema_details` for the target log type — confirm exact field paths and casing before writing any `event.deep_get(...)`.
2. **Sample real events.** `query_data_lake` with a tight `LIMIT` to pull a handful of representative rows. Use them to shape `rule()` logic and as the basis for unit tests.
3. **Check for prior art.** `list_detections --filter LogTypes=...` and `list_global_helpers` so you don't duplicate existing rules or re-implement an existing helper.
4. **Author the detection** in `panther-analysis` (Python + YAML) using the verified field names.
5. **Sanity-check the alert volume.** Once deployed, `get_rule_alert_metrics` shows whether the rule is firing too often / not at all.

### 11.3 Hard rules (do not skip)

- **Public repo discipline still applies.** Anything pulled from `query_data_lake` is real customer/tenant data. **Never paste raw query results into a unit test, commit, PR description, or comment.** Redact account IDs, emails, IPs, hostnames, and identifiers before they leave the MCP tool result — see §1.1.
- **Read-only by default.** For authoring work, scope your API token to read-only (`Query Data Lake`, `View Rules`, `Read Alerts`). Don't grant `Manage Rules` or write scopes unless you specifically need them, and never to a token used by an autonomous agent.
- **Production vs. demo instances.** If you have multiple Panther environments wired up (e.g. `mcp__panther-tr__*` and `mcp__panther-aod__*`), be deliberate about which one you query — production data is more sensitive and rate limits matter.
- **`pat` is still the source of truth for tests.** MCP can fetch a live detection via `get_detection`, but the canonical version lives in this repo. Don't "edit on the live instance" — change the file, run `make test`, and let the upload pipeline propagate.
- **Data-lake queries cost money and time.** Add `LIMIT` clauses, narrow the time range with `p_event_time` predicates, and avoid `SELECT *` on wide tables.

### 11.4 Setup quick reference

If the MCP server isn't already configured:
1. Mint an API token in your Panther instance (Settings → API Tokens) with the minimum scopes you need.
2. Install via Docker or `uvx` per the [README](https://github.com/panther-labs/mcp-panther). Required env vars: `PANTHER_INSTANCE_URL`, `PANTHER_API_TOKEN`.
3. Register the server in your MCP client (e.g. `~/.claude.json` for Claude Code, `.cursor/mcp.json` for Cursor).
4. Verify with a low-impact call like `list_log_type_schemas` before granting broader permissions.

---

## 12. Pull requests

1. Branch from `develop`. Name branches descriptively (e.g. `aws-rds-instance-public-access`).
2. Commit `.py` and `.yml` together — never split a detection across PRs.
3. Run `make fmt && make lint && make test` locally.
4. Open the PR against `develop` (`gh pr create --base develop ...`).
5. Use the [PR template](.github/pull_request_template.md): Background, Changes, Testing.
6. Wait for CODEOWNERS review. If you have merge perms, merge after approval; otherwise comment requesting a code owner merge.

**Don't:**
- Don't open PRs against `main`.
- Don't bundle unrelated detections into one PR.
- Don't include the giant `panther-analysis-*.zip` artifacts at the repo root in your diff (they are build outputs).
- Don't hand-edit files under `indexes/` — they're generated.

---

## 13. Removing or deprecating detections

- Add the deleted detection's `RuleID`/`PolicyID` to `deprecated.txt` so customers can run `make remove-deprecated` to drop it from their instances.
- Run `make check-deprecated` (Panther internal) to validate the file.
- Tag retained-but-discouraged detections with the `Deprecated` tag rather than deleting them outright when downstream users may still rely on them.

---

## 14. Common gotchas

- **`event['field']` will crash on missing fields.** Always use `event.get` / `event.deep_get` with a default.
- **Importing `deep_get` from `panther_base_helpers`** is unnecessary and discouraged — it's a method on `event`.
- **`Filename:` mismatches** between `.yml` and the actual `.py` filename will fail `pat test` with a confusing error.
- **Severity casing** in `Tests:` filters is uppercase (`Severity=CRITICAL`) but in YAML metadata it's title case (`Severity: Critical`). Both are accepted by `pat`.
- **Real PII in test logs** is the most common review blocker for community PRs. Redact before pushing.
- **Forgetting `--base develop`** silently retargets the PR at `main`. Check the base branch on the PR page after creation.
- **Large refactors of `global_helpers/`** can break dozens of detections. Run the full `make test` suite, not a filtered subset.
- **Correlation rule tests pass `pat test` but fail at upload** because real validation requires a live instance — use `pat validate`.
- **Adding new helper modules** requires adding corresponding `*_test.py` files; `make global-helpers-unit-test` enforces this.

---

## 15. Where to look for more detail

- [`style_guides/STYLE_GUIDE.md`](style_guides/STYLE_GUIDE.md) — full Python/metadata style guide
- [`style_guides/CORRELATION_RULES_STYLE_GUIDE.md`](style_guides/CORRELATION_RULES_STYLE_GUIDE.md) — correlation-rule specifics
- [`style_guides/RUNBOOK.md`](style_guides/RUNBOOK.md) — runbook authoring guidance
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the human contributor flow (CLA, PR process)
- [`templates/`](templates/) — starter detections
- [Panther Detections docs](https://docs.panther.com/detections)
- [Panther MCP server docs](https://docs.panther.com/panther-developer-workflows/mcp-server) and [`mcp-panther` repo](https://github.com/panther-labs/mcp-panther) — live-instance tooling for AI clients
- [Anatomy of a High Quality SIEM Rule](https://jacknaglieri.substack.com/p/hq-siem-rules)
