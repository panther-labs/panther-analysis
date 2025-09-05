# Cloud Infrastructure Takeover Test Scenario

## Overview

This test scenario simulates a complete cloud infrastructure takeover attack chain, starting from initial access through a misconfigured resource and escalating to full administrative control with persistent backdoors.

## Attack Chain

### Phase 1: Initial Access (`01_initial_access.sh`)
- **Technique**: Misconfigured public S3 bucket containing EC2 instance credentials
- **Detection Triggers**: Public S3 bucket creation, credential exposure, external access
- **Key Events**: S3 bucket policy changes, public access configuration, unauthorized data access

### Phase 2: Privilege Escalation (`02_privilege_escalation.sh`) 
- **Technique**: IAM role assumption and privilege escalation through trust relationships
- **Detection Triggers**: Role creation, policy attachments, cross-account trust configurations
- **Key Events**: IAM role creation, policy enumeration, elevated permission usage

### Phase 3: Persistence (`03_persistence.sh`)
- **Technique**: Multiple backdoor mechanisms across services and regions
- **Detection Triggers**: Backdoor user creation, Lambda deployment, scheduled execution
- **Key Events**: Administrative user creation, Lambda function deployment, SSM document creation

### Phase 4: Impact Simulation (`04_impact_simulation.sh`)
- **Technique**: Cross-region resource enumeration and high-value data access
- **Detection Triggers**: Bulk resource enumeration, secrets access, cross-region activity
- **Key Events**: Resource discovery, secrets retrieval, infrastructure manipulation

## Usage

### Prerequisites
- AWS CLI configured with appropriate permissions
- `jq` installed for JSON processing
- Bash shell environment

### Running the Scenario

1. **Execute the complete attack chain:**
   ```bash
   chmod +x *.sh
   ./01_initial_access.sh
   ./02_privilege_escalation.sh  
   ./03_persistence.sh
   ./04_impact_simulation.sh
   ```

2. **Clean up all resources:**
   ```bash
   ./cleanup.sh
   ```

### Individual Phase Execution

Each script can be run independently, but they build upon each other:

- Phase 1 creates the initial foothold
- Phase 2 requires credentials from Phase 1
- Phase 3 requires elevated access from Phase 2  
- Phase 4 uses persistence mechanisms from Phase 3

## Detection Coverage

This scenario is designed to trigger the following detection rules:

### Initial Access Detections
- `aws_s3_bucket_public_policy_changes`
- `aws_s3_public_bucket_creation`
- `aws_resource_made_public`

### Privilege Escalation Detections
- `aws_iam_backdoor_role`
- `aws_iam_attach_admin_user_policy`
- `cross_region_activity`

### Persistence Detections
- `aws_iam_create_user`
- `aws_iam_user_key_created`
- `aws_lambda_launched`

### Impact Detections
- `aws_secretsmanager_retrieve_secrets`
- `large_data_transfer_to_external`
- `s3_mass_exfiltration_deletion`

## Safety Features

- **Non-Destructive**: Scripts avoid damaging existing resources
- **Cleanup Automation**: Complete cleanup script removes all test artifacts
- **Resource Tagging**: All created resources are tagged for identification
- **Immediate Cleanup**: Dangerous configurations are removed immediately after testing

## Customization

### Environment Variables
Set these variables to customize the scenario:

```bash
export SCENARIO_BUCKET_PREFIX="custom-test-bucket"
export SCENARIO_REGIONS="us-west-2,us-east-1" 
export SCENARIO_USER_PREFIX="custom-test-user"
```

### Region Configuration
Modify the `REGIONS` array in each script to test different AWS regions.

### Resource Naming
Update the naming variables at the top of each script to match your organization's naming conventions.

## Expected Outcomes

### Successful Execution
- Phase 1: Public S3 bucket created with exposed credentials
- Phase 2: Elevated IAM role created and assumed
- Phase 3: Multiple persistence mechanisms established
- Phase 4: Cross-region enumeration and data access demonstrated

### Detection Validation
Run this query in your SIEM to verify detection coverage:

```sql
SELECT 
    p_event_time,
    aws_region,
    source_ip_address,
    user_identity_arn,
    event_name
FROM panther_logs.public.aws_cloudtrail
WHERE p_occurs_since('1 hour')
  AND (
    event_name IN ('CreateBucket', 'PutBucketPolicy', 'CreateRole', 'AttachRolePolicy') OR
    user_identity_arn LIKE '%test-attack%' OR
    user_identity_arn LIKE '%system-backup-automation%'
  )
ORDER BY p_event_time DESC
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure your AWS CLI profile has sufficient permissions
2. **Resource Already Exists**: Run `cleanup.sh` before retrying
3. **Region Restrictions**: Some regions may have resource limitations
4. **Rate Limiting**: Add delays between API calls if encountering rate limits

### Debug Mode
Run scripts with verbose output:
```bash
bash -x ./01_initial_access.sh
```

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Phase 1:      │    │   Phase 2:      │    │   Phase 3:      │
│ Initial Access  │───▶│   Privilege     │───▶│   Persistence   │
│                 │    │   Escalation    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Public S3       │    │ IAM Role        │    │ Multi-Region    │
│ Credential      │    │ Assumption &    │    │ Backdoor        │
│ Exposure        │    │ Policy Creation │    │ Deployment      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Contributing

To extend this scenario:

1. Follow the existing script structure and naming conventions
2. Add appropriate cleanup procedures
3. Update this README with new detection mappings
4. Test thoroughly before committing

## Security Note

This scenario creates legitimate AWS resources that could be exploited if not properly cleaned up. Always run `cleanup.sh` after testing and verify all resources are removed.