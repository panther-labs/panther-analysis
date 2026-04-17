# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the Panther Analysis repository, containing security detection rules, policies, queries, and supporting infrastructure for the Panther SIEM platform. The codebase is built around a dual-file architecture using Python (`.py`) and YAML (`.yml`) files for each detection.

## Common Development Commands

### Testing
- `make test` - Run all tests (unit tests + panther_analysis_tool tests)
- `pipenv run panther_analysis_tool test` - Run all detection tests
- `pipenv run panther_analysis_tool test --path rules/aws_cloudtrail_rules/` - Test specific path
- `pipenv run panther_analysis_tool test --path rules/aws_cloudtrail_rules/ --filter RuleID=Aws.Example.Rule` - Test specific rule
- `pipenv run panther_analysis_tool test --filter Severity=Critical` - Test by severity
- `pipenv run panther_analysis_tool test --filter LogTypes=AWS.GuardDuty` - Test by log type
- `make global-helpers-unit-test` - Run unit tests for global helpers
- `make data-models-unit-test` - Run unit tests for data models

### Linting and Formatting
- `make lint` - Run all linters (pylint, bandit, isort, black)
- `make fmt` - Format code using isort and black
- `make run-pre-commit-hooks` - Run pre-commit hooks on all files

### Environment Setup
- `make install` - Install all dependencies
- `make install-pre-commit-hooks` - Install git pre-commit hooks
- `pipenv shell` - Activate virtual environment

### Build and Package
- `pipenv run panther_analysis_tool zip` - Create zip file of detections
- `pipenv run panther_analysis_tool zip --filter Severity=Critical` - Zip critical detections only
- `pipenv run panther_analysis_tool upload --api-key KEY --api-host HOST` - Upload to Panther instance

## Repository Architecture

### Core Detection Types
- **Rules** (`/rules/`): Analyze logs to detect malicious activity
- **Policies** (`/policies/`): Check cloud resource configurations for compliance
- **Queries** (`/queries/`): Scheduled queries and signals for threat hunting
- **Correlation Rules** (`/correlation_rules/`): Multi-step attack pattern detection

### Dual-File Structure
Every detection consists of two files:
- `.py` file: Contains the detection logic (required `rule()` or `policy()` function)
- `.yml` file: Contains metadata, configuration, and unit tests

### Global Helpers (`/global_helpers/`)
Reusable utility functions organized by platform:
- `panther_base_helpers`: Core utilities and common functions
- `panther_aws_helpers`: AWS-specific helper functions
- Platform-specific helpers: `panther_okta_helpers`, `panther_github_helpers`, etc.

### Data Models (`/data_models/`)
Normalize log data across different sources with field mappings and transformations.

### Packs (`/packs/`)
Group related detections for deployment. Each pack is a YAML file listing detection IDs.


## Key Development Patterns

### Detection Function Structure
```python
def rule(event):
    # Main detection logic (required)
    return boolean_condition

def title(event):
    # Dynamic alert title (optional)
    return "Alert title"

def alert_context(event):
    # Additional context (optional)
    return {"key": "value"}

def severity(event):
    # Dynamic severity (optional)
    return "HIGH"
```

### Safe Field Access
Always use safe field access methods:
- `event.get('field', default)`
- `event.deep_get('nested', 'field', default=None)`
- Helper functions from `panther_base_helpers`

### Testing Requirements
Every detection must include test cases in the YAML file:
```yaml
Tests:
  - Name: "Test description"
    ExpectedResult: true
    Log: {...}
```

### Helper Function Usage
Import and use global helpers via `GlobalID`:
```python
from panther_base_helpers import panther_base_helpers
from panther_aws_helpers import aws_rule_context
```

## File Organization Conventions

### Naming Patterns
- **RuleID**: `LogType.Source.DetectionName` (e.g., "AWS.CloudTrail.Created")
- **Filename**: Snake case matching detection purpose
- **DisplayName**: Human-readable description in title case

### Directory Structure
- Rules grouped by log source: `aws_cloudtrail_rules/`, `okta_rules/`, etc.
- Policies grouped by service: `aws_iam_policies/`, `aws_s3_policies/`, etc.
- Queries grouped by platform: `aws_queries/`, `crowdstrike_queries/`, etc.

## Important Development Notes

### Required Metadata Fields
- `AnalysisType`: "rule", "policy", or "scheduled_rule"
- `Filename`: Must match the Python filename
- `RuleID`/`PolicyID`: Unique identifier
- `DisplayName`: Human-readable name
- `Enabled`: Boolean flag
- `LogTypes`: Array of log types (for rules)
- `ResourceTypes`: Array of resource types (for policies)
- `Severity`: "INFO", "LOW", "MEDIUM", "HIGH", or "CRITICAL"

### Testing Best Practices
- Include both positive and negative test cases
- Test edge cases and error conditions
- Use realistic log samples from actual sources
- Validate alert context and title generation

### Code Style Requirements
- Python 3.11 compatibility
- Black formatting (line length 100)
- Pylint compliance
- Use of type hints where appropriate
- Comprehensive docstrings for complex functions

### Security Considerations
- Never hardcode credentials or secrets
- Implement proper error handling for external API calls
- Follow principle of least privilege in helper functions