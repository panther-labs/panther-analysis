# panther-analysis Style Guide

## Metadata Best Practices

### RuleID, Filename and DisplayName

- RuleID, Filename and DisplayName should be similar enough to eachother to be able to easily identify a filename by it's RuleID or vice versa.
- RuleID should start with the LogType idenifier followed by a `.`

```yaml
DisplayName: "AWS Compromised IAM Key Quarantine"
RuleID: "AWS.CloudTrail.IAMCompromisedKeyQuarantine"
Filename: aws_iam_compromised_key_quarantine.py
```

### Severity

Review the [Alert Severity Guidelines](https://docs.panther.com/detections/rules#alert-severity) in Panther's documentation.  Consider additional factors that could increase or decrease severity, such as exploitation in the wild, potential for false positives, and actionability.

### Reference

Reference should link to a relevant security research or threat report describing the attack being detected and why you'd want to detect it from a security perspective.  Links to API docs or other generic log source documentation should be avoided.

### Runbook

Runbooks should provide clear triage steps for incident responders.  See [Define Clear Triage Steps](https://jacknaglieri.substack.com/i/148126819/define-clear-triage-steps).

### MITRE ATT&CK Tactics and Techniques

- MITRE ATT&CK tags should be in the form `TA####:T####` or `TA####:T####.###`.
- Add a comment with the Technique name.
- Optionally add the Technique name to Tags as well.

```yaml
Reports:
  MITRE ATT&CK:
    - TA0006:T1556 # Modify Authentication Process
Tags:
  - Modify Authentication Process
```

### Tags

Use tags to label rules for easy classification and reporting.  Some commonly used tags are:

- `Configuration Required` indicates a rule should be configured for your environment before enabling
- MITRE ATT&CK Technique friendly names
- Killchain phase
- Log type
- Relevant security control or compliance framework
- `Deprecated` indicates a rule has been deprecated and should no longer be used

### Unit Tests

- Review Panther's [Testing Documentation](https://docs.panther.com/detections/testing)
- Write tests for both positive and negative cases
- Redact all sensitive information and PII from example logs
- Put tests at the very bottom of the .yml file

## Python Best Practices

### Using `get` and `deep_get`

- Use `event.get('field', '')` for top level fields and `event.deep_get('nested', 'field', default='')` for nested fields.
- Always specify a default return value.  This helps prevent unnecessary `AttributeErrors` when fields are not present in logs.
- Don't directly access fields like `event['field']`, which can also cause `AttributeErrors`.
- Panther's normalized event class has `deep_get` as a built-in method, so it is not necessary to import it from a helper:

```python
# Do this
def rule(event):
    return event.deep_get('foo', default='') == 'bar'

# Instead of this
from panther_base_helpers import deep_get

def rule(event):
    return deep_get(event, 'foo', default='') == 'bar'
```

### Using dynamic functions

Panther's [dynamic auxilliary functions](https://docs.panther.com/detections/rules/python#alert-functions-in-python-detections) are a powerful tool for programattically modifying alerts based on event criteria and should be used when appropriate.

### Use existing alert_context functions

Check for alert_context functions in global_helpers for the LogType you are developing against.  Alert context can be extended in specific rules, for example:

```python
from panther_base_helpers import aws_rule_context

def alert_context(event):
    return aws_rule_context(event) | {'another_field': 'another_value'}
```



