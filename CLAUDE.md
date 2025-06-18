# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the `panther-analysis` repository containing built-in detection rules, policies, queries, and helpers for the Panther SIEM platform. It provides security detections written as code that can be programmatically uploaded to Panther deployments.

## Essential Commands

### Environment Setup
```bash
# Install dependencies
make install

# Install pre-commit hooks (run once after setup)
make install-pre-commit-hooks
```

### Development Workflow
```bash
# Format code
make fmt

# Run linters (pylint, bandit, isort, black)
make lint

# Run all tests
make test

# Run specific test path
pipenv run panther_analysis_tool test --path rules/aws_cloudtrail_rules/

# Run pre-commit hooks manually
make run-pre-commit-hooks
```

### Testing and Validation
```bash
# Test by severity
pipenv run panther_analysis_tool test --filter Severity=Critical

# Test by log type
pipenv run panther_analysis_tool test --filter LogTypes=AWS.GuardDuty

# Create detection zip
pipenv run panther_analysis_tool zip --filter Severity=Critical
```

### Docker Support
```bash
# Build container
make docker-build

# Run tests in container
make docker-test

# Run linting in container
make docker-lint
```

## Repository Architecture

### Detection Types
- **Rules** (`rules/`): Stream-based detections that analyze individual log events
- **Policies** (`policies/`): Resource configuration compliance checks
- **Scheduled Rules**: Aggregate detections based on SQL queries (`queries/` + `rules/`)
- **Correlation Rules** (`correlation_rules/`): Multi-event pattern detection

### Key Directories
- `global_helpers/`: Reusable detection logic and utilities (hard-coded location)
- `data_models/`: Schema definitions and data normalization
- `lookup_tables/`: Reference data for detections
- `templates/`: Example detection templates
- `packs/`: Detection groupings by log source or use case

### Detection Organization
Detection folders follow the pattern `<log_type>_<detection_type>`:
- `aws_cloudtrail_rules/`
- `okta_rules/`
- `github_rules/`
- `aws_s3_policies/`

## Detection File Structure

Each detection requires two files:
1. **Python file** (`.py`): Detection logic
2. **YAML file** (`.yml`): Metadata and configuration

Example: `aws_console_login.py` + `aws_console_login.yml`

## Development Guidelines

### Code Quality
- Always run `make fmt lint test` before committing
- Pre-commit hooks automatically enforce formatting and linting
- Include at least 2 test cases per detection
- Use existing helper functions from `global_helpers/`

### Detection Patterns
- **Rules**: Single-event analysis with `rule(event)` function
- **Signals**: Rules with `CreateAlert: false` for data labeling
- **Scheduled Rules**: SQL queries with Python post-processing

### Essential Functions
- `rule(event)`: Main detection logic (required)
- `title(event)`: Alert title (required for alerting rules)
- `alert_context(event)`: Context for analysts (optional)
- `runbook(event)`: Triage guidance (optional)

### Helper Usage
Import global helpers by their `GlobalID`:
```python
from panther_aws_helpers import aws_cloudtrail_success
```

### Tag Guidelines
Use standardized tags from `.cursor/rules/rule-tags.mdc`:
- Service/Platform: `aws.iam`, `okta`, `github`
- Behaviors: `auth.login_failure`, `resource.delete`
- Compliance: `compliance.soc2`, `compliance.pci_dss`
- MITRE: `initial_access.phishing.spearphishing_link`

## Testing Strategy

### Unit Tests
- Global helpers: `make global-helpers-unit-test`
- Data models: `make data-models-unit-test`

### Detection Tests
Include comprehensive test cases in YAML metadata:
```yaml
Tests:
  - Name: Positive case
    ExpectedResult: true
    Log: { ... }
  - Name: Negative case
    ExpectedResult: false
    Log: { ... }
```

## Style and Formatting

- Black formatter with 100-character line length
- isort for import organization
- Pylint for code quality
- Bandit for security scanning

Configuration in `pyproject.toml`:
```toml
[tool.black]
line-length = 100
target-version = ['py311']
```

## Pipenv Environment

All commands should be run through pipenv:
```bash
pipenv shell  # Enter virtual environment
pipenv run <command>  # Run command in environment
```

## Contributing

1. Follow detection patterns in existing rules
2. Use appropriate log type schemas
3. Include comprehensive tests
4. Follow tag conventions
5. Run full test suite before submitting
6. Sign CLA for contributions

Always reference the [Style Guide](style_guides/STYLE_GUIDE.md) and [Contributing Guidelines](CONTRIBUTING.md) for detailed requirements.

# Detection Syntax Guidelines

## Simple Detections

The following realistic Simple Detection detects AWS root account usage from public IP addresses:

```yaml
AnalysisType: rule
Enabled: true
RuleID: AWS.RootAccount.PublicIPUsageDemo
LogTypes:
  - AWS.CloudTrail
Severity: High
CreateAlert: true
DisplayName: AWS Root Account Usage from Public IP
Description: Detects AWS root account usage from public IP addresses, indicating potential unauthorized access or poor security practices
Detection:
  - KeyPath: userIdentity.type
    Condition: Equals
    Value: Root
  - KeyPath: sourceIPAddress
    Condition: IsIPAddressPublic
  - KeyPath: errorCode
    Condition: IsNull
Tags:
  - AWS
  - Root Account
  - Privilege Escalation
  - MITRE ATT&CK
Reports:
  MITRE ATT&CK:
    - TA0004:T1078.004
    - TA0005:T1078.004
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
Runbook: |
  1. Pivot on the source IP address for recent Okta activity
  2. Review all actions in cloudtrail performed during this root session
  3. If unauthorized, immediately rotate root account credentials
  4. Enable MFA on the root account if not already enabled
SummaryAttributes:
  - sourceIPAddress
  - userAgent
  - eventName
  - eventSource
GroupBy:
  - KeyPath: sourceIPAddress
DedupPeriodMinutes: 60
Threshold: 1
Tests:
  - Name: Root account usage from public IP
    ExpectedResult: true
    Log:
      eventVersion: "1.05"
      userIdentity:
        type: Root
        principalId: "123456789012"
        arn: "arn:aws:iam::123456789012:root"
        accountId: "123456789012"
      eventTime: "2024-01-15T10:30:00Z"
      eventSource: iam.amazonaws.com
      eventName: CreateUser
      sourceIPAddress: 54.8.222.250
      userAgent: aws-cli/2.1.34 Python/3.8.5
      requestParameters:
        userName: suspicious-user
  - Name: Root account usage from private IP (should not alert)
    ExpectedResult: false
    Log:
      eventVersion: "1.05"
      userIdentity:
        type: Root
        principalId: "123456789012"
        arn: "arn:aws:iam::123456789012:root"
        accountId: "123456789012"
      eventTime: "2024-01-15T10:30:00Z"
      eventSource: iam.amazonaws.com
      eventName: CreateUser
      sourceIPAddress: 10.0.1.100
      userAgent: aws-cli/2.1.34 Python/3.8.5
      requestParameters:
        userName: legitimate-user
```

### Workflow

1. Breakdown the user's rule request into appropirate detection logic to cover the desired behavior (if they want a Signal, set CreateAlert to false)
2. Find the correct schema and get a few sample events to ensure you are referencing the right fields in the detection (using tools get_panther_log_type_schema, get_sample_log_events)
3. Choose the appropriate severity level (info for signals, high/critical for immediate response required)
4. Use grouping keys and dedup windows that reduce redundant alerting
5. Always write at least 2 tests for the rules

### Core Concepts

**Match Expressions**: Conditional logic expressions in YAML that return true/false. Used in:
- `Detection` key of Simple Detections
- `InlineFilters` key 
- `Expressions` key of List Comprehension expressions
- `Conditions` key of DynamicSeverities

**Structure**: Match expressions work by:
1. Identifying a key from incoming event with a key specifier
2. Applying a condition that describes the nature of the check  
3. Comparing against a value or list of values

### Key Specifiers

> **Standardization Note:**
> Always use `KeyPath` for both top-level and nested keys for consistency and clarity.

Choose the appropriate key specifier for accessing event data:

```yaml
# Top-level property (standardized)
KeyPath: username

# Nested property (list format)
DeepKey:
  - foo
  - bar
  - baz

# Nested property with path notation and array indexing
KeyPath: foo.bar.baz
KeyPath: foo[*].bar        # wildcard array access
KeyPath: foo.bar[2]        # specific array index
KeyPath: foo.bar[2].baz    # nested after array index
```

### Match Expression Types

#### 1. Key/Value Match Expressions
Compare single event key to a value:
```yaml
- KeyPath: audit_event
  Condition: Equals
  Value: reclassification
```

#### 2. Key/Values Match Expressions  
Check if event value is member of a list:
```yaml
- KeyPath: entity.name
  Condition: IsIn
  Values:
    - Mercury
    - Venus
    - Earth
    - Mars
```

#### 3. Multi-Key Match Expressions
Compare values of two event keys:
```yaml
- Condition: IsGreaterThan
  Values:
    - KeyPath: entity.diameter.distance
    - KeyPath: entity.moons[0].diameter.distance
```

#### 4. List Comprehension Match Expressions
Evaluate conditions against list elements:
```yaml
- KeyPath: entity.moons
  Condition: AnyElement
  Expressions:
    - KeyPath: name
      Condition: Equals
      Value: "Death Star"
    - KeyPath: year_discovered
      Condition: IsGreaterThan
      Value: 2000
```

#### 5. Existence Match Expressions
Check if keys exist:
```yaml
- KeyPath: entity.atmosphere
  Condition: Exists
```

#### 6. Absolute Match Expressions
Always return true/false:
```yaml
- Condition: AlwaysTrue
```

### Common Conditions

#### Scalar Conditions (use with `Value`)
- `Equals` / `DoesNotEqual`
- `IEquals` / `IDoesNotEqual` (case insensitive)
- `StartsWith` / `DoesNotStartWith` / `IStartsWith` / `IDoesNotStartWith`
- `EndsWith` / `DoesNotEndWith` / `IEndsWith` / `IDoesNotEndWith`
- `Contains` / `DoesNotContain` / `IContains` / `IDoesNotContain`
- `IsGreaterThan` / `IsGreaterThanOrEqual` / `IsLessThan` / `IsLessThanOrEqual`
- `Exists` / `DoesNotExist` / `IsNull` / `IsNotNull` / `IsNullOrEmpty` / `IsNotNullOrEmpty`
- IP Address conditions: `IsIPAddress`, `IsIPv4Address`, `IsIPv6Address`, `IsIPAddressPrivate`, `IsIPAddressPublic`, `IsIPAddressInCIDR`

#### List Conditions (use with `Values`)
- `IsIn` / `IsNotIn`

#### List Comprehension Conditions
- `AnyElement` - any element matches
- `AllElements` - all elements match  
- `OnlyOneElement` - exactly one element matches
- `NoElement` - no elements match

#### List of Conditions that may be used with `InlineFilters`
- Equals
- DoesNotEqual
- IsGreaterThan
- IsGreaterThanOrEquals
- IsLessThan
- IsLessThanOrEquals
- Contains
- DoesNotContain
- StartsWith
- EndsWith
- IsIPAddressInCIDR
- IsIPAddressNotInCIDR
- CIDRContainsIPAddresses
- CIDRDoesNotContainIPAddresses
- IsIn
- IsNotIn
- IsIPAddressPublic
- IsIPAddressPrivate
- IsNullOrEmpty
- IsNotNullOrEmpty

### Combinators

Group match expressions with logical operators:

```yaml
# Default combinator is All (AND)
Detection:
  - KeyPath: eventName
    Condition: Equals
    Value: AssumeRole
  - KeyPath: sourceIPAddress
    Condition: IsIPAddressPrivate

# Explicit combinators
Detection:
  - Any:  # OR logic
      - KeyPath: eventName
        Condition: StartsWith
        Value: List
      - KeyPath: eventName
        Condition: StartsWith
        Value: Describe
  - All:  # AND logic (explicit)
      - KeyPath: eventSource
        Condition: Equals
        Value: dynamodb.amazonaws.com
      - KeyPath: errorCode
        Condition: DoesNotExist
```

**Available Combinators:**
- `All` (AND) - all expressions must be true
- `Any` (OR) - any expression must be true  
- `OnlyOne` (XOR) - exactly one expression must be true
- `None` (NOT AND) - no expressions can be true

### Value Types

Values can be integers, floats, booleans, or strings:

```yaml
Value: 2           # integer
Value: 2.5         # float  
Value: true        # boolean
Value: some text   # string (quotes optional)
Value: "some text" # string (explicit quotes)
```

### Best Practices

1. **Start Simple**: Begin with basic key/value matches before adding complexity
2. **Use Appropriate Key Specifiers**: `KeyPath` for all keys (top-level and nested)
3. **Case Sensitivity**: Use `I` prefixed conditions for case-insensitive string matching
4. **IP Address Validation**: Use built-in IP conditions rather than regex
5. **List Comprehension**: Use for complex array evaluations
6. **Combinators**: Group related conditions logically with `All`/`Any`
7. **Testing**: Always include test cases with expected results

### Common Detection Patterns

#### Failed Login Detection
```yaml
Detection:
  - KeyPath: eventName
    Condition: Equals
    Value: ConsoleLogin
  - KeyPath: responseElements.ConsoleLogin
    Condition: Equals
    Value: Failure
```

#### Privilege Escalation
```yaml
Detection:
  - Any:
      - KeyPath: eventName
        Condition: IsIn
        Values:
          - AttachUserPolicy
          - PutUserPolicy
          - AddUserToGroup
  - KeyPath: responseElements.user.userName
    Condition: DoesNotEqual
    Value: expected-service-account
```

#### Unusual Source IP
```yaml
Detection:
  - KeyPath: sourceIPAddress
    Condition: IsIPAddressPublic
  - KeyPath: sourceIPAddress
    Condition: IsNotIn
    Values:
      - 203.0.113.0/24
      - 198.51.100.0/24
```

### Simple Detection Rule Fields Reference

IMPORTANT - YOUR .YML FILE MUST FOLLOW THE FOLLOWING SCHEMA:

| Field Name | Description | Expected Value |
|------------|-------------|----------------|
| `AnalysisType` | Indicates whether this analysis is a rule, scheduled_rule, policy, or global | `rule` |
| `Enabled` | Whether this rule is enabled | Boolean |
| `RuleID` | The unique identifier of the rule | String |
| `LogTypes` | The list of logs to apply this rule to | List of strings |
| `Severity` | Which severity an associated alert should have | One of: `Info`, `Low`, `Medium`, `High`, or `Critical`. This field is overwritten by DynamicSeverities, but is required even if DynamicSeverities is defined |
| `CreateAlert` | Whether the rule should generate rule matches/an alert on matches (default true) | Boolean |
| `Detection` | The list of match expressions to apply to the event data | List of match expressions |
| `DynamicSeverities` | Alternate severities based on custom sets of conditions | List of dynamic severity configurations, consisting of `ChangeTo` and `Conditions` fields. `ChangeTo` is a Severity value and `Conditions` is a list of match expressions |
| `Description` | A brief description of the rule | String |
| `GroupBy` | Set of event values that will be used to deduplicate alerts by | List of event keys |
| `DedupPeriodMinutes` | The time period (in minutes) during which similar events of an alert will be grouped together | 15, 30, 60, 180 (3 hours), 720 (12 hours), or 1440 (24 hours) |
| `DisplayName` | A user-friendly name to show in the Panther Console and alerts. The RuleID will be displayed if this field is not set | String |
| `OutputIds` | Static destination overrides. These will be used to determine how alerts from this rule are routed, taking priority over default routing based on severity | List of strings |
| `Reference` | The reason this rule exists, often a link to documentation | String |
| `Reports` | A mapping of framework or report names to values this rule covers for that framework | Map of strings to list of strings |
| `Runbook` | The actions to be carried out if this rule returns an alert. It's recommended to provide a descriptive runbook, as Panther AI alert triage will take it into consideration | String |
| `SummaryAttributes` | A list of fields that alerts should summarize | List of strings |
| `Threshold` | How many events need to trigger this rule before an alert will be sent | Integer |
| `Tags` | Tags used to categorize this rule | List of strings |
| `Tests` | Unit tests for this rule | List of maps |
| `InlineFilters` | The list of filters in the form of match expressions to filter in data | List of match expressions (limited to filter-compatible versions) |
| `AlertTitle` | An alternate DisplayName that can use event values to create a dynamic title for alerts | String |
| `AlertContext` | Event values to add to the Event under custom keys to create a dynamic alert context | List of key name and key value pairs |

## Python Streaming Rule Syntax

### IMPORTANT GUIDELINES
1. A Python detection MUST CONTAIN TWO FILES: a `.py` file for logic and a `.yml` file for metadata.
2. RULE FUNCTIONS ARE STATELESS and can only process one event at a time.
3. ALWAYS WRITE RULES OUT TO FILES, DO NOT CREATE THEM USING THE CREATE_RULE TOOL
4. READ 1-2 sample `rules/` for the log type you are writing to learn patterns.
5. Thresholding and deduplication are handled by Panther. DO NOT implement this logic in the rule methods.
6. Panther ALSO only passes in classified events that match log_types metadata on the rule. Don't implement this logic.

### Required Functions
`rule(event: Dict[str, Any]) -> bool`: Determines if an alert is sent. Returns `True` if the event matches the rule criteria, `False` otherwise. REQUIRED FOR ALL DETECTIONS. IMPORTANT: GET THE LOG TYPE SCHEMA AND BE SURE TO REFERENCE FIELDS THAT EXIST. 

`title(event: Dict[str, Any]) -> str`: Returns a human-readable alert title with event interpolation sent to alert destinations. THIS IS THE DEFAULT DEDUP() STRING. Do not make it too unique, otherwise too many alerts will be sent. REQUIRED FOR ALL DETECTIONS BUT NOT FOR SIGNALS.

### Optional Functions

`dedup(event: Dict[str, Any]) -> str`: A deduplication key for the alert. OPTIONAL. Only use if specifically instructed by user.

`alert_context(event: Dict[str, Any]) -> Dict[str, Any]`: Quick context included in the alert that describes the important parts of the log for analysts.

ONLY use the following functions when dynamic return values are necessary, based on the event data. Do not declare these functions with simple string return values, and instead set the appropriate YML metadata field.

`severity(event: Dict[str, Any]) -> str`: The severity of the alert (INFO, LOW, MEDIUM, HIGH, CRITICAL). Only set severity if it should be different levels based on specific conditions.

`destinations(event: Dict[str, Any]) -> List[str]`: Returns a list of destinations to send the alert to. Only add this when the user specifies.

`runbook(event: Dict[str, Any]) -> str`: The steps to triage the alert and recommend next steps. Recommended to interpolate important details about events into the runbook.

### Special `event` methods
`event.get()`: To safely access `event` fields that may not exist: `bucket_name = event.get('requestParameters')`

`event.deep_get()`: To access nested `event` fields: `bucket_name = event.deep_get('requestParameters', 'bucketName')` DO NOT IMPORT THIS FUNCTION. IT'S DIRECTLY ACCESSIBLE ON THE EVENT.

`event.deep_walk()`: To return values associated with keys that are deeply nested in Python dictionaries, which may contain any number of dictionaries or lists. If it matches multiple event fields, an array of matches will be returned; if only one match is made, the value of that match will be returned.

### Style Guide
- ONLY ASSIGN VARIABLES WHEN REUSE IS NEEDED! Follow Python coding best practices.
- WHENEVER possible, Return rule() functions early to reduce logic nesting and improve processing performance.
- Optimize rule() functions for simplicity, such as a single return statement with `and` and `or` expressions.

## YML Metadata File Format

The YML file has the following structure:

AnalysisType: # rule, scheduled_rule, correlation_rule, or policy
Enabled: # If the rule is enabled or not
FileName: # the Python file name
RuleID: # or PolicyId
LogTypes: 
- # A list of applicable log types to this rule
Tags: 
- # A list of tags for grouping rules and matches
Tests: 
- # A list of test cases (at least 2)
ScheduledQueries: # only applicable to scheduled rules
Suppressions: # only applicable to policies
CreateAlert: # Signals-only option
Severity: # Info, Low, Medium, High, or Critical
Description:
DedupPeriodMinutes: # The amount of time rule matches are merged into a single alert based on the return values of either title or dedup 
Threshold: # The min number of events that must match the rule before an alert fires
DisplayName:
OutputIds: 
- # A list of destination UUIDs for overridden routing
Reference: # An optional URL to read about research or reference materials for this rule
Runbook: # A few sentences describing how to triage and resolve these alerts. This is read by Panther AI and should be specific.
SummaryAttributes:
- # Fields in the log type schema for quick summarization during alert triage

## Supported Detection Types

### Rules
Directory: (`rules/`)
Description: Streaming Python rules analyze one event at a time and are best applied towards high-fidelity events such as alerts from IDS systems (GuardDuty, Wiz, etc) or high-confidence events like a cronjob containing a wget command or exfiltration from an S3 bucket.
Example Python Filename: aws_iam_user_key_created_demo.py
Example Python Rule Body:
```python
from panther_aws_helpers import aws_cloudtrail_success

def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") == "CreateAccessKey"
        and (
            not event.deep_get("userIdentity", "arn", default="").endswith(
                f"user/{event.deep_get('responseElements', 'accessKey', 'userName', default='')}"
            )
        )
    )


def title(event):
    return (
        f"[{event.deep_get('userIdentity','arn')}]"
        " created API keys for "
        f"[{event.deep_get('responseElements','accessKey','userName', default = '')}]"
    )


def runbook(event):
    return f"""
    Query CloudTrail activity from the new access key ({event.deep_get("responseElements", "accessKey", "accessKeyId", default="key not found")}) at least 2 hours after the alert was triggered and check for data access or other privilege escalation attempts using the aws_cloudtrail table.
    """


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "access_key_id": event.deep_get("responseElements", "accessKey", "accessKeyId", default=""),
        "action": event.get("eventName", ""),
    }
    return context
```

Example YML Metadata Filename: aws_iam_user_key_created_demo.yml
Example YML Metadata Body:
```yml
AnalysisType: rule
Description: Detects AWS API key creation for a user by another user. Backdoored users can be used to obtain persistence in the AWS environment.
DisplayName: "AWS User Backdoor Access Key Created (Demo)"
Enabled: true
CreateAlert: true
Filename: aws_iam_user_key_created_demo.py
Reports:
  MITRE ATT&CK:
    - TA0003:T1098
    - TA0005:T1108
    - TA0005:T1550
    - TA0008:T1550
Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
Severity: High
DedupPeriodMinutes: 60
LogTypes:
  - AWS.CloudTrail
RuleID: "AWS.IAM.Backdoor.UserKeys.Demo"
Threshold: 1
Tags:
  - aws.iam
  - compliance.soc2
Tests:
  - Name: user1 create keys for user1
    ExpectedResult: false
    Log:
      awsRegion: us-east-1
      eventCategory: Management
      eventID: "12345"
      eventName: CreateAccessKey
      eventSource: iam.amazonaws.com
      eventTime: "2022-09-27 17:09:18"
      eventType: AwsApiCall
      eventVersion: "1.08"
      managementEvent: true
      readOnly: false
      recipientAccountId: "123456789"
      requestParameters:
        userName: user1
      responseElements:
        accessKey:
          accessKeyId: ABCDEFG
          createDate: Sep 27, 2022 5:09:18 PM
          status: Active
          userName: user1
      sourceIPAddress: cloudformation.amazonaws.com
      userAgent: cloudformation.amazonaws.com
      userIdentity:
        accessKeyId: ABCDEFGH
        accountId: "123456789"
        arn: arn:aws:iam::123456789:user/user1
        invokedBy: cloudformation.amazonaws.com
        principalId: ABCDEFGH
        sessionContext:
          attributes:
            creationDate: "2022-09-27T17:08:35Z"
            mfaAuthenticated: "false"
          sessionIssuer: {}
          webIdFederationData: {}
        type: IAMUser
        userName: user1
  - Name: user1 create keys for user2
    ExpectedResult: true
    Log:
      awsRegion: us-east-1
      eventCategory: Management
      eventID: "12345"
      eventName: CreateAccessKey
      eventSource: iam.amazonaws.com
      eventTime: "2022-09-27 17:09:18"
      eventType: AwsApiCall
      eventVersion: "1.08"
      managementEvent: true
      readOnly: false
      recipientAccountId: "123456789"
      requestParameters:
        userName: user2
      responseElements:
        accessKey:
          accessKeyId: ABCDEFG
          createDate: Sep 27, 2022 5:09:18 PM
          status: Active
          userName: user2
      sourceIPAddress: cloudformation.amazonaws.com
      userAgent: cloudformation.amazonaws.com
      userIdentity:
        accessKeyId: ABCDEFGH
        accountId: "123456789"
        arn: arn:aws:iam::123456789:user/user1
        invokedBy: cloudformation.amazonaws.com
        principalId: ABCDEFGH
        sessionContext:
          attributes:
            creationDate: "2022-09-27T17:08:35Z"
            mfaAuthenticated: "false"
          sessionIssuer: {}
          webIdFederationData: {}
        type: IAMUser
        userName: user1
```

### Signals
Directory: Also `rules/`
Description: A special mode of a Rule where no alert is generated and events are labeled, dictated by the CreateAlert attribute being set to false. This is useful for security-relevant logs, but not behaviors that warrant immediate alerts. Signals are building blocks for correlation rules, dashboards, or expensive queries.

If a user asks to create a Signal, then:
1. Set `CreateAlert` to false
2. Set `Severity` to INFO
3. ONLY include the rule method
4. Ignore alert-related metadata, such as deduplication

Example Python Rule Filename: panther_jack_login_signal.py
Example Python Rule Body:
```python
def rule(event):
    return (
        event.deep_get("actor", "email", default="") == "jack@panther.io"
        and event.get("actionName", "") == "SIGN_IN"
    )
```

Example YML Metadata Filename: aws_iam_user_key_created_demo.yml
Example YML Metadata Body:
```yml
AnalysisType: rule
Filename: panther_jack_login_signal.py
RuleID: "Panther.Jack.Login.Signal"
DisplayName: "Jack Login to Panther (Signal)"
Enabled: true
LogTypes:
  - Panther.Audit
Tags:
  - user.login
Severity: Info
CreateAlert: false
Description: >
  This signal triggers only when Jack (jack@panther.io) logs into Panther (actionName: 'SIGN_IN'). Use this to monitor Jack's login activity for auditing or behavioral analytics.
SummaryAttributes:
  - actor
  - timestamp
  - action
  - source_ip
  - user_agent
Tests:
  - Name: Jack logs in
    ExpectedResult: true
    Log:
      {
        "p_log_type": "Panther.Audit",
        "actor": {
          "email": "jack@panther.io"
        },
        "p_event_time": "2025-05-13 19:43:18.918",
        "actionName": "SIGN_IN",
        "sourceIP": "",
        "userAgent": null
      }
```


### Scheduled Rules:
Directories: `rules/` for logic/metadata and `queries/` for SQL
Description: An aggregate style detection sourced from scheduled queries (`queries/`) declared in SQL + YAML. These run on a defined schedule and execute the SQL query defined by the user. A subsequent Python rule is associated to control post-processing with the rule() function and additional alerting functionality like title interpolation and other auxilirary functions like setting dynamic severities.

Example Python Rule Filename: notion_many_pages_deleted_sched.py
Example Python Rule Body:
```python
def rule(_):
    return True

def title(event):
    return f"Notion User [{event.get("user")}] deleted multiple pages."
```

Example YML Metadata Filename: notion_many_pages_deleted_sched.yml
Example YML Metadata Body:
```yml
AnalysisType: scheduled_rule
Filename: notion_many_pages_deleted_sched.py
RuleID: "Notion.Many.Pages.Deleted.Sched"
DisplayName: "Notion Many Pages Deleted"
Enabled: true
ScheduledQueries:
  - Notion Many Pages Deleted Query
Tags:
  - Notion
  - Data Security
  - Data Destruction
Severity: Medium
Description: A Notion User deleted multiple pages, which were not created or restored from the trash within the same hour.
DedupPeriodMinutes: 60
Threshold: 10 # Number of pages deleted; please change this value to suit your organization's needs.
Runbook: Possible Data Destruction. Follow up with the Notion User to determine if this was done for a valid business reason.
Reference: https://www.notion.so/help/duplicate-delete-and-restore-content
Tests:
  - Name: query_result
    ExpectedResult: true
    Log:
      {
        "actions": [
          "page.deleted"
        ],
        "id": "1360a5bb-da41-8177-bedb-d015d012392a",
        "page_name": "Newslette",
        "user": "bob.ross@happytrees.com"
      }
```

Example YML Scheduled Query Filename: notion_many_pages_deleted_query.yml
Example YML Scheduled Query Body:
```yml
AnalysisType: scheduled_query
QueryName: Notion Many Pages Deleted Query
Enabled: true
Description: >
  A Notion User deleted multiple pages, which were not created or restored from the trash within the same hour.
Query: |
  SELECT
    event:actor.person.email AS user
    ,ARRAY_AGG(event:type) AS actions
    ,event:details.page_name AS page_name
    ,event:details.target.page_id AS id
  FROM
    panther_logs.public.notion_auditlogs
  WHERE
    p_occurs_since(1 hour)
    AND event:type IN ('page.deleted','page.created','page.restored_from_trash')
    AND event:details.target.type = 'page_id'
    AND page_name != ''
    AND event:actor.type = 'person'
  GROUP BY id, user, page_name
  HAVING 
    actions = ARRAY_CONSTRUCT('page.deleted')
Schedule:
  RateMinutes: 60
  TimeoutMinutes: 2
```
