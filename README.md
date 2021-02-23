<p align="center">
  <a href="https://www.runpanther.io"><img src=".img/panther-logo-github-highres.png" width=75% alt="Panther Logo"/></a>
</p>

<h3 align="center">Built-in Panther Detections</h3>

<p align="center">
  <a href="https://docs.runpanther.io/quick-start">Panther Deployment</a> |
  <a href="https://docs.runpanther.io/writing-detections/panther-analysis-tool">CLI Documentation</a> |
  <a href="https://slack.runpanther.io/">Community Slack Channel</a>
</p>

<p align="center">
  <a href="https://circleci.com/gh/panther-labs/panther-analysis"><img src="https://circleci.com/gh/panther-labs/panther-analysis.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther-analysis" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther-analysis"/></a>
</p>

---

Panther is a security analytics platform built for cloud-focused security teams.

Panther enables teams to define detections as code and programmatically upload them to your Panther deployment.

This repository contains all of Panther's built-in detections  installed by default.

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther-analysis/blob/master/CONTRIBUTING.md) before submitting pull requests.

# Quick Start

```bash
# Clone the repository
git clone git@github.com:panther-labs/panther-analysis.git
cd panther-analysis

# Configure your Python environment
make install
make venv
source venv/bin/activate

# Install dependencies and run your first test!
make deps
panther_analysis_tool test --path aws_cloudtrail_rules/
```

# Getting Started

The examples below demonstrate the local Panther workflow:

```
# Run detection tests
panther_analysis_tool test [-h] [--path PATH]
                                [--filter KEY=VALUE [KEY=VALUE ...]]
                                [--debug]

# Test with a specific path
panther_analysis_tool test --path cisco_umbrella_dns_rules

# Test by severity
panther_analysis_tool test --filter Severity=Critical

# Test by log type
panther_analysis_tool test --filter LogTypes=AWS.GuardDuty

# Create a zip file of detections
panther_analysis_tool zip [-h] [--path PATH] [--out OUT]
                               [--filter KEY=VALUE [KEY=VALUE ...]]
                               [--debug]

# Zip all Critical severity detections
panther_analysis_tool zip --filter Severity=Critical

# Upload detections to your Panther instance
panther_analysis_tool upload [-h] [--path PATH] [--out OUT]
                                  [--filter KEY=VALUE [KEY=VALUE ...]]
                                  [--debug]

# Important: Make sure you have access keys and region settings set for the AWS account running Panther
panther_analysis_tool upload --filter LogTypes=AWS.GuardDuty
```

# Repo Structure

Each folder contains detections in the format of `<log/resource type>_<detecton_type>`:

* **Rules** analyze [logs](https://docs.runpanther.io/log-analysis/supported-logs) to detect malicious activity
* **Policies** represent the desired secure state of a [resource](https://docs.runpanther.io/cloud-security/resources) to detect security misconfigurations
* **Scheduled rules** (coming soon) analyze output of periodically executed [SQL queries](https://docs.runpanther.io/data-analytics/example-queries)

Global helper functions are defined in the `global_helpers` folder. This is a hard coded location and cannot change. However, you may create as many files as you'd like under this path. Simply import them into your detections by the specified `GlobalID`.

Additionally, groups of detections may be linked to multiple "Reports", which is a system for tracking frameworks like CIS, PCI, MITRE ATT&CK, or more.

# Writing Detections

*For a full reference on writing detections, read our [docs](https://docs.runpanther.io/writing-detections/panther-analysis-tool)!*

Each detection has a Python file (`.py`) and a metadata file (`.yml`) of the same name (in the same location), for example:

Example detection rule: `okta_brute_force_logins.py`

```python
def rule(event):
    return (event.get('outcome', {}).get('result', '') == 'FAILURE' and
            event['eventType'] == 'user.session.start')


def title(event):
    return 'Suspected brute force Okta logins to account {} due to [{}]'.format(
        event.get('actor', {}).get('alternateId', 'ID_NOT_PRESENT'),
        event.get('outcome', {}).get('reason', 'REASON_NOT_PRESENT')
    )
```

Example detection metadata: `okta_brute_force_logins.yml`

```yaml
AnalysisType: rule
Filename: okta_brute_force_logins.py
RuleID: Okta.BruteForceLogins
DisplayName: Okta Brute Force Logins
Enabled: true
LogTypes:
  - Okta.SystemLog
Tags:
  - Identity & Access Management
Severity: Medium
...
Threshold: 5
DedupPeriodMinutes: 15
SummaryAttributes:
  - eventType
  - severity
  - displayMessage
  - p_any_ip_addresses
Tests:
  -
    Name: Failed login
    ExpectedResult: true
    Log:
      {
        "eventType": "user.session.start",
        "actor": {
          "id": "00uu1uuuuIlllaaaa356",
          "type": "User",
          "alternateId": "panther_labs@acme.io",
          "displayName": "Run Panther"
        },
        "request": {},
        "outcome": {
          "result": "FAILURE",
          "reason": "VERIFICATION_ERROR"
        }
      }
```

# Customizing Detections

Customizing detections-as-code is one of the most powerful capabilities Panther offers. To manage custom detections, you can create a private fork of this repo.

Upon [tagged releases](https://github.com/panther-labs/panther-analysis/releases), you can pull upstream changes from this public repo.

Follow the instructions [here](https://docs.github.com/en/free-pro-team@latest/github/getting-started-with-github/fork-a-repo) to learn how to get started with forks.

## Getting Updates

When you want to pull in the latest changes from our repository, perform the following steps from your private repo:

```bash
# add the public repository as a remote
git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git

# Pull in the latest changes
# Note: You may need to use the `--allow-unrelated-histories`
#       flag if you did not maintain the history originally
git pull panther-upstream master

# Push the latest changes up to your forked repo and merge them
git push
```

## Continuous Deployment

(coming soon)

# License

This repository is licensed under the AGPL-3.0 [license](https://github.com/panther-labs/panther-analysis/blob/master/LICENSE).
