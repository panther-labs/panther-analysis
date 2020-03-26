<h1 align="center">Panther Analysis</h1>

<p align="center">
  <i>Built-in Panther Detections</i>
</p>

<p align="center">
  <a href="https://docs.runpanther.io">Documentation</a> |
  <a href="https://docs.runpanther.io/quick-start">Quick Start</a>
</p>

<p align="center">
  <a href="https://panther-labs-oss-slackin.herokuapp.com/">Chat with us on Slack!</a>
  <a href="https://circleci.com/gh/panther-labs/panther-analysis"><img src="https://circleci.com/gh/panther-labs/panther-analysis.svg?style=svg" alt="CircleCI"/></a>
  <a href="https://cla-assistant.io/panther-labs/panther-analysis" alt="CLA Assistant"><img src="https://cla-assistant.io/readme/badge/panther-labs/panther-analysis"/></a>
</p>

---

This repository contains open-source [Panther](https://github.com/panther-labs/panther) policies and rules.

During the initial deployment of Panther, all of the policies and rules published here are uploaded. This provides a set of out-of-the-box policies and rules to establish a strong detection baseline. See the [Panther documentation](https://docs.runpanther.io/quick-start) for how to override this default behavior if desired.

## Analysis with Policies and Rules

Within this repository, you will find a collection of rules and policies. Policies define the compliant and secure state of a cloud Resource, whereas Rules perform analysis on log data. These can be used in conjunction to ensure a cloud environment is configured securely, as well as detect possible malicious activity.

### Standards

Currently, many of our rules and policies are based on Center for Internet Security (CIS) recommended best practices. As we grow, we intend to add support for more and varied compliance frameworks. Feel free to contribute policies and rules that help you meet your own compliance requirements!

### Included Policies

We include the following policy bundles:

  - CIS
    - These policies cover the CIS benchmarks for AWS Cloud Infrastructure, specifically controls 1.x, 2.x, and 4.x. These policies can help an organization check compliance with CIS recommended best practices.
  - Managed
    - These policies cover many of the similar concerns as the AWS Config Managed rules. These policies can help an organization meet baseline good practice configurations as recommended by AWS.
  - S3
    - These policies cover S3 security configurations in general. These policies can help an organization ensure best security practices are in use with regards to their S3 buckets.

### Included Rules

We include the following rule bundles:

  - CIS
    - These rules monitor CloudTrail log data and cover the CIS benchmarks for AWS Cloud Infrastructure, specifically controls 3.x. These rules can help an organization ensure compliance with CIS recommended best practices.
  - S3 Access Logs
    - These rules monitor S3 access logs, and can serve as examples for additional S3 access log related rules
  - VPC Flow Logs
    - These rules monitor VPC Flow Logs, and can serve as examples for additional VPC flow log related rules.

### Policy & Rule Management

Customizing Policies and Rules to meet your organization's needs is one of the most powerful capabilities Panther offers. This can present additional challenges when it comes to managing these policies and rules, however. In order to help manage custom configurations of Policies & Rules internally, we create a private fork of this public repo. All development we do in the public repo, and all custom configuration we do in the private repo. At tagged releases, we pull the changes from the public repo into the private repo. Here is how we set this up:

#### Setup - GitHub

The following setup will assume that you are using GitHub to host your git repositories.

  - Navigate to github.com while logged in to a user in your organization
  - Select the `+` button drop down in the top right corner, and select `Import repository`
  - In the `Your old repository's clone URL` section add our public repo: `https://github.com/panther-labs/panther-analysis.git`
  - Make sure the `Owner` drop down is set to your organization, and then add a `Name` (such as `panther-analysis-internal`)
  - Set the `Privacy` radio button to `Private` (unless you want your configurations to be public)
  - You will be redirected to a loading page while the repository is being imported. After a short while, you the repository will be available and you can clone it and begin development normally.

#### Setup - git command line

The following setup will use the git command line directly.

  - Create a new blank repository on your git server. For this example, we will call the repo `private-analysis`

Perform these steps if you are able to push to master:
  - Clone the public repository (recommend cloning into /tmp or similar): `git clone --bare git@github.com:panther-labs/panther-analysis.git`
  - Enter the public repository: `cd panther-analysis.git`
  - Mirror the public repository to the private repository: `git push --mirror git@your-server.com:your-org/private-analysis.git`

Perform these steps if you are not able to push to master:
  - Clone the private repository: `git clone git@your-server.com:your-org/private-analysis.git`
  - Enter the private repository: `cd private-analysis`
  - Add the public repository as an upstream remote of this repository: `git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git`
  - Create and checkout a branch: `git checkout -b initial-commit`
  - Pull in the public repository. Note, if you have any files (such as an autogenerated README) in your private repository, you will need to manually merge conflicts after this step: `git pull --allow-unrelated-histories panther-upstream master`
  - Push your commit up to master: `git push --set-upstream origin initial-commit`
  - Merge your commit into master. If you are following the fork and pull request workflow, this will involve opening a PR, possibly getting approval, and then merging.

#### Updating

Now that you have a private repository will all the default policies and rules, you can customize away to your hearts content. When you are ready pull in the newest changes from our public repository, perform the following steps from within your private repo:

  - If you have not already done so, add the public repository as a remote: `git remote add panther-upstream git@github.com:panther-labs/panther-analysis.git`
  - Pull in the latest changes (in a local branch if you cannot push to master): `git pull panther-upstream master`
    - You may need to use the `--allow-unrelated-histories` flag if you did not maintain the history originally
  - Push the latest changes up and merge them: `git push`

## Panther Analysis Tool

The `panther_analysis_tool` is a Python command line interface for testing, packaging, and deploying Panther Policies and Rules. Consider checking it out here [panther\_analysis\_tool](https://github.com/panther-labs/panther_analysis_tool) for help managing your Panther analysis packs.

## Writing Policies

Each Panther Policy consists of a Python body and a YAML or JSON specification file.

In the Python body, returning a value of `True` indicates the resource being evaluated is compliant. Returning a value of `False` indicates the resource is non-compliant, and an alert may be sent or an auto-remediation may be performed as a result.

The specification file defines the attributes of the Policy. This includes settings such as `Enabled`, `Severity`, and `ResourceTypes`, as well as metadata such as `DisplayName`, `Tags`, and `Runbook`. See the [Writing Local Policies](https://docs.runpanther.io/policies/writing-local) documentation for more details on what fields may be present, and how they are configured.

`example_policy.py`
```python
def policy(resource):
  return True
```

`example_policy.yml`
```yaml
AnalysisType: policy
Enabled: true
Filename: example_policy.py
PolicyID: Example.Policy.01
ResourceTypes:
  - Resource.Type.Here
Severity: Low
DisplayName: Example Policy to Check the Format of the Spec
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
Tests:
  -
    Name: Name to describe our first test.
    Schema: Resource.Type.Here
    ExpectedResult: true/false
    Resource:
      Key: Values
      For: Our Resource
      Based: On the Schema
```

The requirements for the Policy body and specification files are listed below.

The Python body MUST:
  - Be valid Python3
  - Define a function `policy` that accepts one argument
  - Return a `bool` from the `policy` function

The Python body SHOULD:
  - Name the argument to the `policy` function `resource`

The Python body MAY:
  - Import standard Python3 libraries
  - Define additional helper functions as needed
  - Define variables and classes outside the scope of the `policy` function

The specification file MUST:
  - Be valid JSON/YAML
  - Define an `AnalysisType` field with the value `policy`
  - Define the additional following fields:
    - Enabled
    - FileName
    - PolicyID
    - ResourceTypes
    - Severity


## Writing Rules

Rules are very similar to Policies, and require a similar Python body and JSON or YAML specification file as Policies require.

One very important distinction between Policies and Rules is the meaning of the return value. For Rules, returning a value of `False` indicates that the event being evaluated should not be alerted on. Returning a value of `True` indicates that the event is suspicious, and an alert may be sent or an auto-remediation may be performed as a result.

`example_rule.py`
```python
def rule(event):
  return False
```

`example_rule.yml`
```yaml
AnalysisType: rule
Enabled: true
Filename: example_rule.py
PolicyID: Example.Rule.01
ResourceTypes:
  - Log.Type.Here
Severity: Low
DisplayName: Example Rule to Check the Format of the Spec
Tags:
  - Tags
  - Go
  - Here
Runbook: Find out who changed the spec format.
Reference: https://www.link-to-info.io
Tests:
  -
    Name: Name to describe our first test.
    ResourceType: Log.Type.Here
    ExpectedResult: true/false
    Resource:
      Key: Values
      For: Our Log
      Based: On the Schema
```

The requirements for the Rule body and specification files are listed below.

The Python body MUST:
  - Be valid Python3
  - Define a function `rule` that accepts one argument
  - Return a `bool` from the `rule` function

The Python body SHOULD:
  - Name the argument to the `rule` function `event`

The Python body MAY:
  - Import standard Python3 libraries
  - Define additional helper functions as needed
  - Define variables and classes outside the scope of the `rule` function

The specification file MUST:
  - Be valid JSON/YAML
  - Define an `AnalysisType` field with the value `rule`
  - Define the additional following fields:
    - Enabled
    - FileName
    - PolicyID
    - ResourceTypes
    - Severity

## Testing
Both policies and rules can define unit tests, which can be used to ensure they are performing as expected on test data before pushing them live to a production environment. This can help guarantee correctness of code, as well as protect against exceptions and unexpected behavior. To run these tests, consider using the `panther_analysis_tool` directly or making use of the `Makefile` provided here. For using the `panther_analysis_tool` directly, please refer to the [documentation](https://github.com/panther-labs/panther_analysis_tool).

The benefit of using this Makefile is that (if run from this directory), it will automatically include the `aws_globals` helper functions.

The `make test` target will test all policies and rules in the packs already in this repo, and this functionality can be expanded by modifying the `Makefile`. The `make test-single` target takes a single parameter, `pack`, and will test just the contents of that directory. Example usage:

```bash
make test-single pack=osquery_rules
[INFO]: Testing analysis packs in /var/folders/p3/l1lxj0057dj01rw34rfr0r8h0000gn/T/tmp.Bq2hgZNI

OSquery.Mac.ALFDisabled
	[PASS] ALF Disabled
	[PASS] ALF Enabled

OSquery.Mac.OSXAttacks
	[PASS] App running on Desktop that is watching keyboard events
	[PASS] App is running from approved path
```

Note that unit testing currently does not support function call mocking. We recommend not writing unit tests for functions that make network calls, as the behavior may be unexpected.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Contributing

We welcome all contributions! Please read the [contributing guidelines](https://github.com/panther-labs/panther-analysis/blob/master/CONTRIBUTING.md) before submitting pull requests.

## License

This repository is licensed under the Apache-2.0 [license](https://github.com/panther-labs/panther-analysis/blob/master/LICENSE).
