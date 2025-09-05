# Defense Evasion: SIEM Detection Disabling Attack Scenario

## Overview

This scenario demonstrates a sophisticated defense evasion attack where an attacker uses leaked AWS session tokens to systematically disable security detection rules in Panther before performing malicious activities.

**Attack Type**: Initial Access → Defense Evasion → Persistence → Data Exfiltration → Impact  
**Timeline**: 4-hour attack window (limited by session token validity)  
**MITRE ATT&CK Tactics**: TA0001 (Initial Access), TA0005 (Defense Evasion), TA0003 (Persistence), TA0010 (Exfiltration), TA0040 (Impact)

## Initial Compromise Vector

**Scenario**: Developer accidentally commits AWS session token to public GitHub repository

**Compromise Details**:

- **Token Type**: Temporary STS credentials (ASIA* access key)
- **Role**: `PowerUserRole` (assumed via Okta SAML federation)
- **Session Duration**: 4 hours (expires at 18:00 UTC)
- **Discovery Method**: Automated GitHub scanning by attacker
- **Validation**: `sts:GetCallerIdentity` confirms active session
- **MFA Status**: `mfaAuthenticated: false` (session already established)
- **Source IP**: `198.51.100.123` (attacker's infrastructure)

**Key Evasion Advantages**:

- No console login alerts (bypasses typical compromise detection)
- No Okta authentication logs (existing session reused)
- Temporary credentials appear "legitimate" in CloudTrail
- 4-hour window provides sufficient time for multi-phase attack

## Attack Scenario

### Phase 0: Initial Access (T1078 - Valid Accounts)

**Objective**: Validate compromised session and assess privileges

**Actions** (14:00-14:02):

1. **Session Validation**: `sts:GetCallerIdentity`
   - Confirms active session for `PowerUserRole`
   - No alert (legitimate API call)

2. **Privilege Enumeration**:
   - `iam:GetUser`, `iam:ListAttachedUserPolicies`
   - `iam:SimulatePrincipalPolicy` (test permissions)
   - Discovers Panther admin access via attached policies

3. **Environment Reconnaissance**:
   - `organizations:DescribeOrganization`
   - `sts:GetSessionToken` (test if session can be extended)

### Phase 1: Defense Evasion (T1562 - Impair Defenses)

**Objective**: Disable security monitoring to create blind spots

**Actions**:

1. **Disable Multiple Detection Rules** (14:03-14:05)
   - Uses `UPDATE_DETECTION_STATE` action in Panther
   - Disables 5+ CloudTrail-related detection rules:
     - `AWS.CloudTrail.Stopped.Demo`
     - `AWS.IAM.BackdoorRole.Demo`
     - `AWS.IAM.AttachAdminUserPolicy.Demo`
     - `AWS.S3.MassExfiltrationDeletion.Demo`
     - `AWS.SecretsManager.RetrieveSecrets.Demo`
   - **Alert Triggered**: `Panther.MultipleDetectionsDisabledHigh.Demo` (HIGH severity)

2. **Disable CloudTrail Logging** (14:05:00)
   - `cloudtrail:StopLogging` on security audit trail
   - **No Alert**: Rule was disabled in Step 1

3. **Disable Macie Monitoring** (14:06:00)
   - `macie2:UpdateMacieSession` (pause monitoring)
   - `macie2:ArchiveFinding` (hide existing findings)
   - **No Alert**: Rule was disabled in Step 1

### Phase 2: Persistence (T1078 - Valid Accounts, T1098 - Account Manipulation)

**Objective**: Establish persistent access mechanisms

**Actions**:
4. **Create Backdoor IAM Role** (14:10:00)

- `iam:CreateRole` → "SystemMaintenanceRole"
- `iam:UpdateAssumeRolePolicy` → Principal: "*" with ExternalId condition
- `iam:AttachRolePolicy` → AdministratorAccess
- **No Alert**: Rule was disabled

5. **Create Additional Access Keys** (14:12:00)
   - `iam:CreateAccessKey` for current user
   - `iam:CreateUser` → "backup-service-account"
   - `iam:CreateAccessKey` for new service account
   - **Limited Alerts**: Some user creation rules may still exist

### Phase 3: Secret Discovery and SIEM Credential Harvesting (T1530 - Data from Cloud Storage)

**Objective**: Discover and extract sensitive credentials for lateral movement

**Actions**:
6. **Enumerate AWS Secrets Manager** (14:15:00)
   - `secretsmanager:ListSecrets` across US regions (us-east-1, us-east-2, us-west-1, us-west-2)
   - Discovers high-value targets:
     - `log-forwarder-api-credentials` - Panther log ingestion API keys
     - `siem-integration-credentials` - SIEM platform authentication
   - **No Alert**: Rule was disabled

7. **Retrieve SIEM Integration Secrets** (14:16:00)
   - `secretsmanager:GetSecretValue` on `siem-integration-credentials`
   - Extract Panther SIEM credentials:
     - Username: `log-forwarder-svc`
     - Password: `P@ssw0rd!2024#Secure`
     - Client ID: `siem-client-12345`
     - Client Secret: `siem-secret-abcdef1234567890`
     - Auth URL: `https://auth.company.com/oauth2/token`
   - **No Alert**: Rule was disabled

8. **Retrieve Log Forwarding API Keys** (14:17:00)
   - `secretsmanager:GetSecretValue` on `log-forwarder-api-credentials`
   - Extract Panther API credentials:
     - API Key: `sk-1234567890abcdef1234567890abcdef12345678`
     - Organization ID: `org_1234567890abcdef`
     - API Endpoint: `https://logs.panther.ai/api/v1/ingest`
   - **No Alert**: Rule was disabled

### Phase 4: SIEM Lateral Movement and Control (T1078 - Valid Accounts)

**Objective**: Pivot into SIEM platform to expand control and evade detection

**Actions**:
9. **Authenticate to Panther SIEM** (14:20:00)
   - Use extracted credentials to authenticate to `https://auth.company.com/oauth2/token`
   - Obtain OAuth2 bearer token for SIEM API access
   - Validate access with `GET /api/v1/users/me` call
   - **Alert**: Potential unusual API authentication patterns (if monitoring exists)

10. **Escalate SIEM Privileges** (14:22:00)
    - Use service account to access Panther admin functions
    - `POST /api/v1/detections/bulk-disable` - Disable additional detection rules
    - `GET /api/v1/alerts` - Access all organizational alerts and incidents
    - `DELETE /api/v1/alerts/{alert-id}` - Delete evidence of previous alerts
    - **No Alert**: Internal SIEM actions not monitored in disabled environment

11. **Inject False Log Data** (14:25:00)
    - Use harvested API key to inject false positive logs via `/api/v1/ingest`
    - Create noise in legitimate channels to mask ongoing activities
    - Inject benign CloudTrail events to normalize suspicious activity patterns
    - **No Alert**: Log injection appears as legitimate forwarding

### Phase 5: Impact and Evidence Destruction (T1485 - Data Destruction, T1070 - Indicator Removal)

**Objective**: Destroy evidence, maintain persistence, and cause operational impact

**Actions**:
12. **SIEM Evidence Destruction** (14:28:00)
    - Delete alert history via SIEM API: `DELETE /api/v1/alerts/bulk`
    - Modify detection rule definitions to hide future similar attacks
    - Clear audit logs in SIEM platform: `DELETE /api/v1/audit-logs`
    - **No Alert**: SIEM self-modification not monitored

13. **AWS Evidence Destruction** (14:30:00)
    - `s3:DeleteBucket` → company-secrets-backup
    - `cloudtrail:DeleteTrail` → security-audit-trail
    - `logs:DeleteLogGroup` → /aws/security/alerts
    - `secretsmanager:DeleteSecret` → Remove accessed secrets to hide tracks
    - **No Alert**: Rules disabled, evidence destruction undetected

## Detection Coverage

### ✅ Alerts That Fire

- `panther_multiple_detections_disabled_high_demo.yml` (HIGH) - Triggers on 5+ rule disables
- Potential `panther_log_source_deleted_high_demo.yml` if log sources are affected

### ❌ Alerts Silenced by Rule Disabling

- `aws_cloudtrail_stopped_demo.yml` - CloudTrail logging disabled
- `aws_iam_backdoor_role_demo.yml` - Backdoor role creation
- `aws_secretsmanager_retrieve_secrets_demo.yml` - Secrets access (critical for SIEM pivot)
- `aws_secretsmanager_enumerate_secrets_demo.yml` - Secret enumeration across regions
- `panther_api_unusual_authentication_demo.yml` - SIEM API authentication anomalies
- `panther_bulk_rule_modification_demo.yml` - Bulk detection rule changes via API
- `aws_macie_evasion_demo.yml` - Macie monitoring disabled

## Key Learning Points

1. **Session Token Compromise is Dangerous**: Temporary credentials bypass typical login monitoring
2. **SIEM Protection is Critical**: Attackers target the monitoring system first  
3. **Secrets Manager = Crown Jewels**: Credential stores contain keys to entire infrastructure
4. **Lateral Movement via Stored Credentials**: SIEM credentials enable platform takeover
5. **Rule Disabling vs Deletion**: Disabling is stealthier than deletion
6. **Aggregation Rules Work**: Multiple small actions can indicate big problems
7. **Cross-Platform Attack Chains**: AWS → Secrets → SIEM creates blind spots
8. **Temporal Correlation**: 4-hour window shows coordinated, methodical attack
9. **Privilege Requirements**: Attack requires admin-level AWS and SIEM access
10. **API-Based Attacks**: Service accounts and API keys enable silent operations
11. **Evidence Destruction**: SIEM control allows comprehensive cleanup
12. **GitHub Scanning**: Attackers actively scan for leaked credentials

## Defensive Recommendations

### Immediate Actions

1. **Credential Scanning**: Monitor public repositories for leaked AWS tokens
2. **Session Token Monitoring**: Alert on temporary credentials from unusual locations
3. **Secrets Manager Protection**: Monitor and alert on secret enumeration and retrieval
4. **Cross-Reference Secret Access**: Correlate AWS Secrets Manager access with subsequent authentication events
5. **SIEM API Monitoring**: Track unusual API authentication patterns and bulk operations
6. **Strict RBAC**: Limit who can disable/delete detection rules in both AWS and SIEM
7. **Immutable Deployments**: Use CI/CD for rule changes, not UI or API
8. **Rule Change Monitoring**: Treat rule modifications as high-priority security events
9. **Separation of Duties**: Require approval for bulk rule changes
10. **Service Account Monitoring**: Track service account usage patterns and anomalies

### Long-term Strategy

1. **Zero Trust for SIEM**: Monitor the monitors with external systems
2. **Credential Segmentation**: Separate AWS and SIEM credentials, avoid storing SIEM creds in AWS
3. **Backup Detection**: Deploy detection rules across multiple systems and platforms  
4. **Behavioral Baselines**: Track normal vs abnormal administrative activity across platforms
5. **Secret Rotation**: Regularly rotate service account credentials and API keys
6. **Cross-Platform Correlation**: Monitor for credential access followed by authentication elsewhere
7. **Incident Response**: Have procedures for compromised SIEM scenarios and credential exposure
8. **Defense in Depth**: Layer security controls across cloud and SIEM platforms

## Real-world Applicability

This scenario reflects actual attack patterns where adversaries:

- Exploit leaked credentials from public repositories (increasing trend)
- Target security infrastructure first (SolarWinds, Kaseya)  
- Pivot through credential stores to access multiple platforms
- Use legitimate service accounts and APIs for malicious purposes
- Leverage temporary credentials to bypass login monitoring
- Chain together cloud and SIEM access for comprehensive control
- Operate within session expiry windows to avoid suspicion
- Layer multiple evasion techniques across platforms
- Destroy evidence across multiple systems to avoid attribution

The 4-hour timeline is realistic for a motivated attacker with compromised session tokens, demonstrating how quickly an attacker can pivot from initial AWS access to complete SIEM control, reflecting actual credential exposure windows and multi-platform attack chains.

## Testing Instructions

### Prerequisites
1. **Setup**: Ensure demo detection rules are deployed and enabled
2. **Create Test Secrets**: Run `test_scenarios/aws-data-exfil/create_test_secrets.sh <aws-profile>` to create the SIEM integration secrets
3. **SIEM Access**: Configure test Panther instance with API access enabled

### Execution
1. **Initial Compromise**: Simulate compromised session token discovery
2. **Defense Evasion**: Follow Phase 1 timeline to disable detection rules
3. **Persistence**: Execute Phase 2 backdoor creation activities  
4. **Secret Discovery**: Execute Phase 3 AWS Secrets Manager enumeration and retrieval
5. **SIEM Pivot**: Execute Phase 4 SIEM authentication and privilege escalation
6. **Impact**: Execute Phase 5 evidence destruction across platforms

### Validation
1. **Alert Verification**: Confirm which alerts fire and which are silenced
2. **SIEM Logs**: Verify SIEM API access and modifications are logged
3. **Cross-Platform Correlation**: Test detection of AWS-to-SIEM lateral movement
4. **Timeline Analysis**: Validate temporal correlation across platforms

### Cleanup
1. **Re-enable Detection Rules**: Restore all disabled AWS and SIEM detection rules
2. **Delete Test Secrets**: Remove created secrets from AWS Secrets Manager
3. **SIEM Reset**: Restore SIEM alert history and rule configurations
4. **Document Findings**: Record lessons learned and detection gaps

## Files in This Scenario

- `README.md` - This documentation
- `attack_timeline.json` - Detailed event timeline for simulation
- `expected_alerts.json` - Which alerts should/shouldn't fire
- `cleanup_script.sh` - Reset environment after testing
- `../aws-data-exfil/create_test_secrets.sh` - Creates SIEM integration secrets for testing
