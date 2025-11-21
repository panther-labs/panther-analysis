# Detection Runbook Guidelines

This document provides guidance for writing effective Runbook fields in Panther detection rules. Runbooks are read by Panther AI during alert triage to guide investigation steps.

## Purpose

Runbooks provide **actionable investigation steps** that Panther AI can execute autonomously when triaging alerts. Well-written runbooks help the AI:
1. Gather relevant context about the alert
2. Identify patterns and correlations
3. Assess whether activity is benign or malicious
4. Provide evidence-based recommendations

## Writing Effective Runbooks

### Core Principles

1. **Be Specific**: Provide concrete, actionable steps with clear parameters
2. **Use Timeframes**: Always specify time windows for searches (e.g., "24 hours before", "30 minutes around")
3. **Reference Alert Fields**: Use specific field names from the alert (e.g., `userIdentity:arn`, `sourceIPAddress`, `p_alert_id`)
4. **Focus on Context**: Guide the AI to gather evidence that answers "is this benign or risky?"

### Structure

Each runbook should contain **2-3 focused investigation steps** that build on each other:

```yaml
Runbook: |
  1. Find all API calls by this user in the 24 hours before the alert
  2. Check if the source IP is associated with known cloud provider IP ranges or VPN endpoints
  3. Look for other alerts from this user or IP address in the past 7 days
```

## Good vs. Bad Examples

### ✅ GOOD Examples

**Specific and Actionable:**
```yaml
Runbook: |
  1. Query AWS CloudTrail for all API calls by the actor ARN in the 6 hours before and after this alert
  2. Check if the source IP appears in threat intelligence feeds or is associated with known VPN/proxy services
  3. Search for other alerts with the same rule ID and actor ARN in the past 30 days
```

**Clear Timeframes:**
```yaml
Runbook: |
  1. Find all S3 GetObject events for this bucket in the 1 hour window around the alert time
  2. Identify if the requester ARN has accessed this bucket in the past 90 days
  3. Check if the accessed objects contain sensitive data classifications
```

**Concrete Parameters:**
```yaml
Runbook: |
  1. Query Okta system logs for all authentication events by this user in the 2 hours before the alert
  2. Check if the source IP matches any previously seen IP addresses for this user
  3. Look for concurrent login attempts from different geographic locations
```

### ❌ BAD Examples

**Too Vague:**
```yaml
Runbook: |
  1. Search for related user activity
  2. Check the source IP
  3. See if this was legitimate
```
*Problem: No timeframes, no specific fields, unclear what "related" or "legitimate" means*

**Missing Context:**
```yaml
Runbook: |
  1. Review CloudTrail logs
  2. Check IP reputation
```
*Problem: No timeframe, no specific user/resource, too generic*

**Tool-Specific Commands:**
```yaml
Runbook: |
  1. Use sqlTool to query aws_cloudtrail table for errorCode field
  2. Use enrichmentTool on sourceIPAddress
  3. Use alertListTool with p_rule_id filter
```
*Problem: Too prescriptive about tools - let AI decide which tool to use*

## Investigation Patterns

### User Behavior Analysis
```yaml
Runbook: |
  1. Find all API calls by the user ARN in the 24 hours before the alert to establish normal behavior
  2. Identify if this action has been performed by this user in the past 90 days
  3. Check for other alerts or suspicious activity from this user in the past 7 days
```

### Resource Access Patterns
```yaml
Runbook: |
  1. Query for all access attempts to this S3 bucket in the 1 hour window around the alert
  2. Determine if the accessing principal has legitimate access to this bucket based on past 30 days of activity
  3. Check if the accessed object keys match sensitive data patterns
```

### Network/IP Analysis
```yaml
Runbook: |
  1. Find all API calls from the source IP in the 6 hours before and after the alert
  2. Check if the IP is associated with known cloud providers, VPNs, or corporate network ranges
  3. Look for geographic inconsistencies in login locations for this user
```

### Privilege Escalation Investigation
```yaml
Runbook: |
  1. Query IAM policy changes for this user or role in the 48 hours before the alert
  2. Find all API calls using the newly granted permissions in the 24 hours after the policy change
  3. Check if the user has performed similar privilege escalation actions in the past 90 days
```

### Data Exfiltration Investigation
```yaml
Runbook: |
  1. Calculate total data transferred by this user to external destinations in the 24 hours before and after the alert
  2. Compare data transfer volume to the user's 30-day average baseline
  3. Identify if the destination IPs or domains are associated with cloud storage or file sharing services
```

### Failed Authentication Analysis
```yaml
Runbook: |
  1. Count failed authentication attempts for this user in the 1 hour before the first failure
  2. Check if successful authentication occurred after the failed attempts from a different IP
  3. Look for password reset or MFA changes for this user in the 24 hours around the alert
```

## Available Investigation Capabilities

Panther AI has access to the following capabilities (you don't need to specify tool names):

| Capability | What It Does | Example Runbook Step |
|------------|--------------|---------------------|
| **Log Search** | Search any log type by filters | "Find all AWS CloudTrail events by the user ARN in the 24 hours before the alert" |
| **Structured Queries** | Query data lake tables with SQL-like syntax | "Query S3 server access logs for all GetObject operations on this bucket in the past hour" |
| **Detection Details** | Get detection rule source code and metadata | "Review the detection rule logic to understand what threshold triggered this alert" |
| **Related Alerts** | Find alerts by rule, user, IP, or other fields | "Find all other alerts from this rule for the same user in the past 30 days" |
| **Alert Details** | Get complete alert context and events | "Retrieve the full alert details including all events and context fields" |
| **Historical AI Analysis** | Search past AI triage responses | "Check if similar privilege escalation patterns have been analyzed before" |
| **Schema Information** | Get log type field definitions | "Review the Okta SystemLog schema to understand available fields for correlation" |
| **Indicator Enrichment** | Check IP, domain, hash reputation | "Check if the source IP is associated with known threat actors or proxy services" |
| **Data Profiling** | Analyze column value distributions | "Summarize the most common event names for this user in the past 7 days" |

## Special Considerations

### Time Window Selection

- **Recent suspicious activity**: 1-6 hours before/after
- **Establishing baselines**: 30-90 days of history
- **Correlation searches**: 24 hours to 7 days
- **Long-term patterns**: 90 days

### Field References

Always reference specific fields from the alert or log schema:
- ✅ `userIdentity:arn`
- ✅ `sourceIPAddress`
- ✅ `p_alert_id`
- ✅ `requestParameters:bucketName`
- ❌ "the user" (ambiguous)
- ❌ "the IP" (unclear which IP field)

### Context Building

Good runbooks help build a narrative:
1. **What happened?** (immediate context)
2. **Is this normal?** (baseline comparison)
3. **What else is suspicious?** (correlation)

## Template Examples

### Generic Template
```yaml
Runbook: |
  1. [Action] by [specific field] in [timeframe]
  2. [Check/Compare/Verify] [specific condition]
  3. [Search/Look for] [related activity] in [timeframe]
```

### AWS CloudTrail Template
```yaml
Runbook: |
  1. Query CloudTrail for all API calls by [userIdentity:arn] in the [timeframe]
  2. Check if [sourceIPAddress] matches known [condition]
  3. Find other alerts for this [user/resource/action] in the [timeframe]
```

### Authentication Template
```yaml
Runbook: |
  1. Count [auth events] for [user] in [timeframe before alert]
  2. Check if [condition about IP/location/device]
  3. Look for [successful auth/password changes/account modifications] in [timeframe]
```

## Testing Your Runbook

Ask yourself:
1. Can Panther AI execute these steps without additional clarification?
2. Do the steps provide evidence for determining if activity is malicious?
3. Are timeframes and field names specific and accurate?
4. Would these steps help a human analyst investigate this alert?

If you answered "yes" to all four questions, your runbook is well-written.

---

*For more information on writing detections, see the main [CLAUDE.md](CLAUDE.md) documentation.*
