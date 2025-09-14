# AWS Data Exfiltration Test Scenarios

## Overview

This test scenario simulates a comprehensive data exfiltration attack by a malicious insider with legitimate AWS access. The scenario creates realistic attack patterns that security detection rules should identify, helping validate the effectiveness of your SIEM rules for detecting:

- **Malicious insider threat creation**: Creating seemingly legitimate service accounts with excessive privileges
- **Permission enumeration**: Systematically discovering available AWS permissions and resources
- **Data exfiltration**: Bulk downloading of sensitive data from S3 buckets and Secrets Manager
- **Privilege escalation**: Creating additional IAM users and access keys for persistent access
- **Cross-region reconnaissance**: Enumerating secrets and resources across multiple AWS regions

### Attack Flow

1. **Initial Access**: Malicious insider creates a "backup-service-account" with broad AWS managed policies
2. **Reconnaissance**: Enumerates IAM permissions, S3 buckets, EC2 instances, and secrets across US regions
3. **Data Harvesting**: Downloads training data from S3 buckets and extracts secrets from Secrets Manager
4. **Persistence**: Creates additional IAM users and access keys for continued access
5. **Exfiltration**: Saves all collected data to local temporary directories for offline analysis

### Artifacts Generated

This scenario generates the following CloudTrail events and artifacts that should trigger security detections:

**IAM Events:**
- `CreateUser` - Creating backup-service-account with production tags
- `AttachUserPolicy` - Attaching multiple AWS managed policies (S3FullAccess, EC2FullAccess, SecretsManagerReadWrite)
- `CreateAccessKey` - Generating programmatic access credentials
- `ListAttachedUserPolicies`, `ListUserPolicies` - Permission enumeration activities
- `GetCallerIdentity` - Identity verification calls

**S3 Events:**
- `ListBuckets` - Enumerating all S3 buckets in the account
- `ListObjects`, `GetObject` - Bulk downloading of training data from targeted buckets

**Secrets Manager Events:**
- `ListSecrets` - Cross-region enumeration of all secrets (us-east-1, us-east-2, us-west-1, us-west-2)
- `GetSecretValue` - Retrieving secret contents for log forwarding and SIEM integration credentials
- `CreateSecret`, `UpdateSecret` - Creating and modifying test secrets with realistic payloads

**EC2 Events:**
- `DescribeInstances` - Enumerating EC2 resources
- `RunInstances` (DryRun) - Testing EC2 launch permissions

**File System Artifacts:**
- Downloaded S3 bucket contents in `/tmp/*/s3_data/`
- Extracted secrets saved as text files in `/tmp/*/secrets_data/`
- Temporary directories containing exfiltrated data

## Scripts

### `create_malicious_user.sh`
Creates a test IAM user with elevated privileges that mimics a malicious insider scenario:
- Creates user named `backup-service-account` with production tags
- Attaches AWS managed policies for S3, EC2, and Secrets Manager full access
- Generates access keys for programmatic access

### `cleanup_malicious_user.sh`
Cleans up the test environment by:
- Detaching all AWS managed policies from the test user
- Deleting all access keys associated with the user
- Removing the IAM user completely

### `create_test_secrets.sh`
Creates test secrets in AWS Secrets Manager across multiple US regions:
- Requires an AWS profile as argument
- Creates realistic log forwarding and SIEM integration credentials
- Deploys secrets to us-east-1, us-east-2, us-west-1, and us-west-2

### `update_test_secrets.sh`
Updates existing test secrets with modified values:
- Modifies secrets created by `create_test_secrets.sh`
- Updates log forwarding API credentials and SIEM integration settings
- Operates across all US regions

### `enumerate_aws_permissions.py`
Python script for enumerating AWS permissions and testing various operations:
- Supports dry-run mode for safe testing
- Configurable AWS profile and region support
- Color-coded output for better visibility
- Designed to trigger security detection rules through permission enumeration

## Usage

### Basic Test Scenario
1. Create the malicious user:
   ```bash
   ./create_malicious_user.sh
   ```

2. Create test secrets:
   ```bash
   ./create_test_secrets.sh <aws-profile>
   ```

3. Run permission enumeration:
   ```bash
   python3 enumerate_aws_permissions.py --profile <aws-profile> --region us-west-2
   ```

4. Clean up when done:
   ```bash
   ./cleanup_malicious_user.sh
   ```

### Dry Run Mode
For safe testing without making actual changes:
```bash
python3 enumerate_aws_permissions.py --dry-run --profile <aws-profile>
```

## Security Considerations

⚠️ **WARNING**: These scripts create privileged AWS resources and should only be used in test environments. Always run cleanup scripts after testing to remove created resources.

- Scripts create IAM users with broad permissions
- Test secrets contain realistic but fake credentials
- Permission enumeration may trigger security alerts (this is expected behavior)
- Always use dedicated test AWS accounts, never production environments

## Detection Rules

These scenarios are designed to trigger the following types of detection rules:
- Unusual IAM user creation patterns
- Excessive privilege escalation
- Secrets Manager bulk access patterns
- Permission enumeration activities
- Data exfiltration behaviors

## Requirements

- AWS CLI configured with appropriate permissions
- Python 3.x with boto3, click, and colorama packages
- Valid AWS credentials and profiles
- IAM permissions to create/modify users, policies, and secrets

## Contributing

When adding new test scenarios:
1. Follow the existing naming conventions
2. Include both setup and cleanup scripts
3. Add appropriate error handling and colored output
4. Document the detection patterns the scenario should trigger
5. Test in isolated environments only