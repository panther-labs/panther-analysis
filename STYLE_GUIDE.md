# panther-analysis Style Guide

This style guide highlights essential best practices for writing python rules and alert metadata. For a more detailed guide, visit [Writing Python Detections](https://docs.panther.com/detections/rules/python) in the Panther documentation.

## Metadata best practices

### RuleID, Filename, and DisplayName

- `RuleID`, `Filename`, and `DisplayName` should all be similar to one another. A good litmus test is: If you have the `RuleID`, would you be able to identify the related Python file (its `Filename`), and vice versa?
- `RuleID` should start with the log type identifier followed by a `.`

Example:
```yaml
DisplayName: "AWS Compromised IAM Key Quarantine"
RuleID: "AWS.CloudTrail.IAMCompromisedKeyQuarantine"
Filename: aws_iam_compromised_key_quarantine.py
```

### Severity

Review the [Alert Severity Guidelines](https://docs.panther.com/detections/rules#alert-severity) in Panther's documentation.  Consider additional factors that could increase or decrease severity, such as exploitation in the wild, potential for false positives, and actionability.

### Reference

The `Reference` value should be a link to a relevant security or threat research report that describes the attack this rule detects, including why it is valuable to detect it from a security perspective. Avoid generic documentation links, such as general API or log source pages.

### Runbook

The `Runbook` value should provide clear triage steps for incident responders.  See [Define Clear Triage Steps](https://jacknaglieri.substack.com/i/148126819/define-clear-triage-steps).

### MITRE ATT&CK reports

- MITRE ATT&CK tactics and techniques should be in the form `TA####:T####` or `TA####:T####.###`
- Add a comment with the Technique name
- Optionally add the Technique name to Tags as well

Example:
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

### Unit tests

- Review Panther's [Testing Documentation](https://docs.panther.com/detections/testing)
- Write tests for both positive and negative cases
- Redact all sensitive information and PII from example logs
- Put tests at the very bottom of the .yml file

## Python best practices

### Use `get` and `deep_get`

- Use `event.get('field', '')` for top level fields and `event.deep_get('nested', 'field', default='')` for nested fields
- Always specify a default return value.  This helps prevent unnecessary `AttributeErrors` when fields are not present in logs
- Don't directly access fields like `event['field']`, which can also cause `AttributeErrors`
- Panther's normalized event class has `deep_get` as a built-in method, so it is not necessary to import it from a helper.  For example:

```python
# Do this
def rule(event):
    return event.deep_get('foo', default='') == 'bar'

# Instead of this
from panther_base_helpers import deep_get

def rule(event):
    return deep_get(event, 'foo', default='') == 'bar'
```

### Use dynamic functions

Panther's [dynamic auxiliary functions](https://docs.panther.com/detections/rules/python#alert-functions-in-python-detections) are a powerful tool for programattically modifying alerts based on event criteria and should be used when appropriate.

### Use existing `alert_context` functions

Check for `alert_context` functions in `global_helpers` for the LogType you are developing against.  Alert context can be extended in specific rules, for example:

```python
from panther_aws_helpers import aws_rule_context

def alert_context(event):
    return aws_rule_context(event) | {'another_field': 'another_value'}
```



