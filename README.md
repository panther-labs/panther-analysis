<p align="center">
  <a href="https://panther.com"><img src=".img/panther-logo-github-highres.png" width=40% alt="Panther Logo"/></a>
</p>

<h3 align="center">Built-in Panther Detections</h3>

<p align="center">
  <a href="https://docs.panther.com/quick-start">Panther Deployment</a> |
  <a href="https://docs.panther.com/writing-detections/panther-analysis-tool">CLI Documentation</a>
</p>

<p align="center">
  <a href="https://github.com/panther-labs/panther-analysis/actions/workflows/lint-test.yml"><img src="https://github.com/panther-labs/panther-analysis/actions/workflows/lint-test.yml/badge.svg" alt="GitHub Actions Link"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther-analysis" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther-analysis"/></a>
</p>

---

Panther is a modern SIEM built for security operations at scale.

With Panther, teams can define detections as code and programmatically upload them to your Panther deployment. This repository contains all detections developed by the Panther Team and the Community.

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther-analysis/blob/main/CONTRIBUTING.md) before submitting pull requests.

# Quick Start

## Clone the repository

```bash
git clone git@github.com:panther-labs/panther-analysis.git
cd panther-analysis
```

### Repo Structure

Each folder contains detections in the format of `<log/resource type>_<detecton_type>`:

* **Rules** analyze [logs](https://docs.panther.com/data-onboarding/supported-logs) to detect malicious activity
* **Policies** represent the desired secure state of a [resource](https://docs.panther.com/cloud-scanning) to detect security misconfigurations
* **Scheduled rules** analyze output of periodically executed [SQL queries](https://docs.panther.com/data-analytics/example-queries)

## Configure your Python environment

```bash
python3 -m pip install pipenv
echo "PYTHON_BIN_PATH=\"$(python3 -m site --user-base)/bin\"" >> ~/.zprofile
echo "export PATH=\"$PATH:$PYTHON_BIN_PATH\"" >> ~/.zprofile
. ~/.zprofile
make install
pipenv shell # Optional, this will spawn a subshell containing pipenv environment variables. Running pipenv run before commands becomes optional after this step
````

### Install dependencies and run your first test

```bash
make install
pipenv run panther_analysis_tool test --path rules/aws_cloudtrail_rules/
```

### Run detection tests

```bash
pipenv run panther_analysis_tool test [-h] [--path PATH]
                                [--filter KEY=VALUE [KEY=VALUE ...]
                                [--debug]
```

### Test with a specific path

```bash
pipenv run panther_analysis_tool test --path rules/cisco_umbrella_dns_rules
```

### Test by severity

```bash
pipenv run panther_analysis_tool test --filter Severity=Critical
```

### Test by log type

```bash
pipenv run panther_analysis_tool test --filter LogTypes=AWS.GuardDuty
```

### Create a zip file of detections

```bash
pipenv run panther_analysis_tool zip [-h] [--path PATH] [--out OUT]
                               [--filter KEY=VALUE [KEY=VALUE ...]]
                               [--debug]
```

### Zip all Critical severity detections

```bash
pipenv run panther_analysis_tool zip --filter Severity=Critical
````

### Upload detections to your Panther instance

```bash
# Note: Set your AWS access keys and region env variables before running the `upload` command

export AWS_REGION=us-east-1
pipenv run panther_analysis_tool upload [-h] [--path PATH] [--out OUT]
                                  [--filter KEY=VALUE [KEY=VALUE ...]]
                                  [--debug]
```

Global helper functions are defined in the `global_helpers` folder. This is a hard coded location and cannot change. However, you may create as many files as you'd like under this path. Simply import them into your detections by the specified `GlobalID`.

Additionally, groups of detections may be linked to multiple "Reports", which is a system for tracking frameworks like CIS, PCI, MITRE ATT&CK, or more.

## Using [Visual Studio Code](https://code.visualstudio.com/)

If you are comfortable using the Visual Studio Code IDE, the `make vscode-config` command can configure VSCode to work with this repo.

In addition to this command, you will need to install these vscode add-ons:

1. [Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python)
2. [Black Formatter](https://marketplace.visualstudio.com/items?itemName=ms-python.black-formatter)
3. [Pylint](https://marketplace.visualstudio.com/items?itemName=ms-python.pylint)
4  [Bandit](https://marketplace.visualstudio.com/items?itemName=nwgh.bandit)
5. [YAML](https://marketplace.visualstudio.com/items?itemName=redhat.vscode-yaml)

You will also need Visual Studio's [code](https://code.visualstudio.com/docs/setup/mac#_launching-from-the-command-line) configured to open Visual Studio from your CLI.

`make vscode-config` will configure:

1. Configure VSCode to use the python virtual environment for this repository.
1. Resolve local imports like global_helpers, which permits code completion via Intellisense/Pylance
1. Creates two debugging targets, which will give you single-button push support for running `panther_analysis_tool test` through the debugger.
1. Installs JSONSchema support for your custom panther-analysis schemas in the `schemas/` directory. This brings IDE hints about which fields are necessary for schemas/custom-schema.yml files.
1. Installs JSONSchema support for panther-analysis rules in the `rules/` directory. This brings IDE hints about which fields are necessary for rules/my-rule.yml files.
1. Configures `Black` and `isort` settings for auto-formatting on save (thus reducing the need to run `make fmt` on all files)
1. Configures `pylint` settings for linting when changes are made
    - Ensure that `"pylint.lintOnChange": true` is present in the User-level VSCode settings (`Cmd+Shift+P` -> `Preferences: Open Settings (JSON)`)
2. Configures `Bandit` settings for linting when files are opened

```shell
user@computer:panther-analysis: make vscode-config
```

## Using Docker

To use Docker, you can run some of the `make` commands provided to run common panther-analysis workflows. Start by building the container, then you can run any command you want from the image created. If you would like to run a different command, follow the pattern in the Makefile.

  ``` bash
  make docker-build
  make docker-test
  make docker-lint
  ```

Please note that you only need to rebuild the container if you update your `Pipfile.lock` changes, because the dependencies are install when the image is built. The subsequent test and lint commands are run in the image by mounting the current file system directory, so it is using your local file system.

## Using Windows

If you are on a Windows machine, you can use the following instructions to perform the standard panther-analysis workflow.

1. Install [docker desktop](https://docs.docker.com/desktop/install/windows-install/) for Windows.
2. Using `make` is recommended. If you would like to use `make`, first install [chocolately](https://chocolatey.org/install), a standard Windows packaging manager.
3. With chocolately, install the make command:

    ```shell
    choco install make
    ```

4. `make` should now be installed and added to your PATH. Try running a `make docker-build` to get started.

# Writing Detections

*For a full reference on writing detections, read our [guide](https://docs.panther.com/writing-detections)!*

Each detection has a Python file (`.py`) and a metadata file (`.yml`) of the same name (in the same location), for example:

Example detection rule: `okta_brute_force_logins.py`

```python
def rule(event):
    return (event.get('outcome', {}).get('result', '') == 'FAILURE' and
            event.get('eventType') == 'user.session.start')


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
RuleID: "Okta.BruteForceLogins"
DisplayName: "Okta Brute Force Logins"
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

Follow the instructions [here](https://docs.panther.com/panther-developer-workflows/ci-cd/detections-repo) to get started with either a public fork or a private cloned repo to host your custom detection content.

## Getting Updates

When you want to pull in the latest changes from this repository, we recommend leveraging the [included GitHub Action](https://docs.panther.com/panther-developer-workflows/ci-cd/detections-repo/public-fork#keeping-in-sync-with-upstream).

If you wish to sync manually, the process below can be run from a terminal.

```bash
# add the public repository as a remote
git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git

# Pull in the latest changes
# Note: You may need to use the `--allow-unrelated-histories`
#       flag if you did not maintain the history originally
git pull panther-upstream main 

# Push the latest changes up to your forked repo and merge them
git push
```

# License

This repository is licensed under [Apache License, Version 2.0](https://github.com/panther-labs/panther-analysis/blob/main/LICENSE.txt).
