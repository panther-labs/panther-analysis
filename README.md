<p align="center">
  <a href="https://www.runpanther.io"><img src=".img/panther-logo-github-highres.png" width=75% alt="Panther Logo"/></a>
</p>

<h3 align="center">Built-in Panther Detections</h3>

<p align="center">
  <a href="https://docs.runpanther.io/quick-start">Panther Deployment</a> |
  <a href="https://docs.runpanther.io/user-guide/analysis/panther-analysis-tool">CLI Documentation</a> |
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
make venv
source venv/bin/activate

# Install dependencies and run your first test!
make deps
panther_analysis_tool test --path aws_cloudtrail_rules/
```

## Quick Commands

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

# Structure

Each folder contains detections in the format of `<log/resource type>_<detecton_type>`:

* **Rules** analyze [logs](https://docs.runpanther.io/log-analysis/supported-logs) to detect malicious activity
* **Policies** represent the desired secure state of a [resource](https://docs.runpanther.io/cloud-security/resources) to detect security misconfigurations
* **Scheduled rules** (coming soon) analyze output of periodically executed [SQL queries](https://docs.runpanther.io/enterprise/data-analytics/example-queries)

Global helper functions are defined in the `global_helpers` folder. This is a hard coded location and cannot change. However, you may create as many files as you'd like under this path. Simply import them into your detections by the specified `GlobalID`.

Additionally, groups of detections may be linked to multiple "Reports", which is a system for tracking frameworks like CIS, PCI, MITRE ATT&CK, or more.

# Usage

*For a full reference on writing detections, read our [docs](https://docs.runpanther.io/user-guide/analysis/panther-analysis-tool)!*

Each detection has a Python file (`.py`) and a metadata file (`.yml`) of the same name (in the same location), for example:

`okta_brute_force_logins.py`

```python
def rule(event):
    return (event['outcome']['result'] == 'FAILURE' and
            event['eventType'] == 'user.session.start')


def title(event):
    return 'Suspected brute force Okta logins to account {} due to [{}]'.format(
        event['actor']['alternateId'], event['outcome']['reason'])
```

`okta_brute_force_logins.yml`

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

# Managing Internal Detections

Customizing detections-as-code is one of the most powerful capabilities Panther offers.

To manage custom internal configurations, create a private fork of this repo.

Upon [tagged releases](https://github.com/panther-labs/panther-analysis/releases), users can pull upstream changes from this public repo into your own private repo.

## GitHub Setup

The instructions below will help with configuring your own private repository.

### UI Setup

- Navigate to github.com while logged in to a user in your organization
- Select the `+` button drop down in the top right corner, and select `Import repository`
- In the `Your old repository's clone URL` section add our public repo: `https://github.com/panther-labs/panther-analysis.git`
- Make sure the `Owner` drop down is set to your organization, and then add a `Name` (such as `panther-analysis-internal`)
- Set the `Privacy` radio button to `Private` (unless you want your configurations to be public)
- You will be redirected to a loading page while the repository is being imported. After a short while, you the repository will be available and you can clone it and begin development normally.

### Command-Line

Create a new blank repository on your git server. For this example, we will call the repo `private-analysis`

Perform these steps if you are able to push to the primary branch:

```bash
# Clone the public repository
git clone --bare git@github.com:panther-labs/panther-analysis.git

# Enter the public repository
cd panther-analysis.git

# Mirror the public repository to the private repository
git push --mirror git@your-server.com:your-org/private-analysis.git
```

Perform these steps if you are not able to push to the primary branch:

```bash

# Clone the private repository
git clone git@your-server.com:your-org/private-analysis.git

# Enter the private repository
cd private-analysis

# Add the public repository as an upstream remote of this repository:
git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git

# Create and checkout a branch
git checkout -b initial-commit

# Pull in the public repository.
# Note, if you have any autogenerated files in your private
# repository, you will need to merge conflicts after this step:
git pull --allow-unrelated-histories panther-upstream master

# Push your commit up to master
git push --set-upstream origin initial-commit

# Merge your commit into master
```

## Getting Updates

When you are ready pull in the newest changes from our public repository, perform the following steps from within your private repo:

```bash
# add the public repository as a remote
git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git

# Pull in the latest changes
# Note: You may need to use the `--allow-unrelated-histories`
#       flag if you did not maintain the history originally
git pull panther-upstream master

# Push the latest changes up and merge them
git push
```

## Continuous Deployment

(coming soon)

# License

This repository is licensed under the Apache-2.0 [license](https://github.com/panther-labs/panther-analysis/blob/master/LICENSE).
