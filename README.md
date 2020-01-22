# Panther Analysis

This repository is a combination of open source policies and rules meant to be run with [Panther](https://github.com/panther-labs/panther), as well as the `panther-cli` tool which can be used to test and package these policies and rules without having to go through the Panther web interface.

During initial deployments of Panther, the default configuration is to load all the policies and rules published during version releases of this project. This provides a set of out-of-the-box policies and rules to get analysis up and running. See the Panther documentation for how to override this default behavior if desired.

## Analysis - Policies & Rules

Within the `analysis` directory, you will find a collection of rules and policies. Policies define the compliant and secure state of a cloud Resource, whereas Rules perform analysis on log data. These can be used in conjunction to ensure a cloud environment is configured securely, as well as detect possible malicious activity.

### Standards

Currently, many of our rules and policies are based on Center for Internet Security (CIS) reccomended best practices. As we grow, we intend to add support for more and varied compliance frameworks. Feel free to contribute policies and rules that help you meet your own compliance requirements!

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

## Panther CLI Tool

`panther-cli` is a Python command line interface for testing and packaging Panther Policies and Rules. This enables policies and rules to be managed in code and tracked via version control systems such as git or svn. This is also useful for devops and security personnel who prefer CLI management and configuration over web app interfaces.

### Installation

Setup your environment:

```bash
$ make venv
$ source venv/bin/activate
$ make deps
```

Use the [pip](https://pip.pypa.io/en/stable/) package manager (locally for now) to install `panther-cli`.

```bash
pip install -e .
```

### Writing Policies

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


### Writing Rules

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

### Commands and Usage

```bash
$ panther-cli --help

usage: panther-cli [-h] {test,zip} ...

Panther CLI

positional arguments:
  {test,zip}
    test      Validate policy specifications and run policy tests.
    zip       Create an archive of local Policies for uploading to Panther.

optional arguments:
  -h, --help  show this help message and exit

$ panther-cli test --policies tests/fixtures/valid_policies/

[INFO]: Testing Policies in tests/fixtures/valid_policies/

Testing policy 'AWS.IAM.MFAEnabled'
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

$ panther-cli zip --policies tests/fixtures/valid_policies/ --output-path tmp

[INFO]: Testing Policies in tests/fixtures/valid_policies/

Testing policy 'AWS.IAM.MFAEnabled'
	[PASS] Root MFA not enabled fails compliance
	[PASS] User MFA not enabled fails compliance

[INFO]: Zipping policies in tests/fixtures/valid_policies/ to tmp
[INFO]: /Users/user_name/panther-cli/tmp/panther-policies-2019-01-01T16-00-00.zip
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[Apache](https://choosealicense.com/licenses/apache-2.0/)
