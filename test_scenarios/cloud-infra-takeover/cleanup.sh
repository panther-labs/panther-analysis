#!/bin/bash

# File: test_scenarios/cloud-infra-takeover/cleanup.sh
# Cleanup script for Cloud Infrastructure Takeover test scenario

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Starting cleanup of Cloud Infrastructure Takeover test scenario${NC}"
echo -e "${YELLOW}[*] This will remove all resources created during the attack simulation${NC}"

# Function to safely delete resources with error handling
safe_delete() {
    local cmd="$1"
    local description="$2"
    
    echo -e "${GREEN}[+] $description${NC}"
    eval $cmd 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}    ✓ Success${NC}"
    else
        echo -e "${YELLOW}    ! Failed or resource not found${NC}"
    fi
}

# 1. Clean up S3 bucket from initial access phase
echo -e "\n${YELLOW}[*] Phase 1 Cleanup: S3 Bucket${NC}"
if [ -f /tmp/cloud-infra-takeover-bucket-name.txt ]; then
    BUCKET_NAME=$(cat /tmp/cloud-infra-takeover-bucket-name.txt)
    echo -e "${GREEN}[+] Cleaning up S3 bucket: $BUCKET_NAME${NC}"
    
    # Empty bucket first
    safe_delete "aws s3 rm s3://$BUCKET_NAME --recursive" "Emptying S3 bucket"
    
    # Delete bucket policy
    safe_delete "aws s3api delete-bucket-policy --bucket $BUCKET_NAME" "Removing bucket policy"
    
    # Delete bucket
    safe_delete "aws s3 rb s3://$BUCKET_NAME" "Deleting S3 bucket"
    
    # Clean up temp file
    rm -f /tmp/cloud-infra-takeover-bucket-name.txt
else
    echo -e "${YELLOW}[!] No bucket name file found - skipping S3 cleanup${NC}"
fi

# 2. Clean up escalation roles from privilege escalation phase
echo -e "\n${YELLOW}[*] Phase 2 Cleanup: Escalation Roles${NC}"
if [ -f /tmp/cloud-infra-takeover-escalation-role.txt ]; then
    while IFS= read -r role_name; do
        if [ -n "$role_name" ]; then
            echo -e "${GREEN}[+] Cleaning up role: $role_name${NC}"
            
            # Detach all managed policies
            ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name $role_name --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
            if [ -n "$ATTACHED_POLICIES" ]; then
                for policy_arn in $ATTACHED_POLICIES; do
                    safe_delete "aws iam detach-role-policy --role-name $role_name --policy-arn $policy_arn" "Detaching policy $policy_arn"
                done
            fi
            
            # Delete inline policies
            INLINE_POLICIES=$(aws iam list-role-policies --role-name $role_name --query 'PolicyNames[]' --output text 2>/dev/null)
            if [ -n "$INLINE_POLICIES" ]; then
                for policy_name in $INLINE_POLICIES; do
                    safe_delete "aws iam delete-role-policy --role-name $role_name --policy-name $policy_name" "Deleting inline policy $policy_name"
                done
            fi
            
            # Delete role
            safe_delete "aws iam delete-role --role-name $role_name" "Deleting role $role_name"
        fi
    done < /tmp/cloud-infra-takeover-escalation-role.txt
    
    rm -f /tmp/cloud-infra-takeover-escalation-role.txt
else
    echo -e "${YELLOW}[!] No escalation role file found - skipping role cleanup${NC}"
fi

# 3. Clean up persistence mechanisms
echo -e "\n${YELLOW}[*] Phase 3 Cleanup: Persistence Mechanisms${NC}"
if [ -f /tmp/cloud-infra-takeover-backdoor-user.txt ]; then
    
    # Read persistence artifacts
    BACKDOOR_USER=$(sed -n '1p' /tmp/cloud-infra-takeover-backdoor-user.txt)
    BACKDOOR_ROLE=$(sed -n '2p' /tmp/cloud-infra-takeover-backdoor-user.txt)
    LAMBDA_FUNCTION=$(sed -n '3p' /tmp/cloud-infra-takeover-backdoor-user.txt)
    SSM_DOCUMENT=$(sed -n '4p' /tmp/cloud-infra-takeover-backdoor-user.txt)
    
    # Clean up backdoor user
    if [ -n "$BACKDOOR_USER" ]; then
        echo -e "${GREEN}[+] Cleaning up backdoor user: $BACKDOOR_USER${NC}"
        
        # Delete access keys
        ACCESS_KEYS=$(aws iam list-access-keys --user-name $BACKDOOR_USER --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
        for key in $ACCESS_KEYS; do
            safe_delete "aws iam delete-access-key --user-name $BACKDOOR_USER --access-key-id $key" "Deleting access key $key"
        done
        
        # Detach managed policies
        ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name $BACKDOOR_USER --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
        for policy_arn in $ATTACHED_POLICIES; do
            safe_delete "aws iam detach-user-policy --user-name $BACKDOOR_USER --policy-arn $policy_arn" "Detaching policy from user"
        done
        
        # Delete inline policies
        INLINE_POLICIES=$(aws iam list-user-policies --user-name $BACKDOOR_USER --query 'PolicyNames[]' --output text 2>/dev/null)
        for policy_name in $INLINE_POLICIES; do
            safe_delete "aws iam delete-user-policy --user-name $BACKDOOR_USER --policy-name $policy_name" "Deleting inline user policy"
        done
        
        # Delete user
        safe_delete "aws iam delete-user --user-name $BACKDOOR_USER" "Deleting backdoor user"
    fi
    
    # Clean up backdoor role
    if [ -n "$BACKDOOR_ROLE" ]; then
        echo -e "${GREEN}[+] Cleaning up backdoor role: $BACKDOOR_ROLE${NC}"
        
        # Detach managed policies
        ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name $BACKDOOR_ROLE --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
        for policy_arn in $ATTACHED_POLICIES; do
            safe_delete "aws iam detach-role-policy --role-name $BACKDOOR_ROLE --policy-arn $policy_arn" "Detaching policy from role"
        done
        
        # Delete inline policies
        INLINE_POLICIES=$(aws iam list-role-policies --role-name $BACKDOOR_ROLE --query 'PolicyNames[]' --output text 2>/dev/null)
        for policy_name in $INLINE_POLICIES; do
            safe_delete "aws iam delete-role-policy --role-name $BACKDOOR_ROLE --policy-name $policy_name" "Deleting inline role policy"
        done
        
        # Delete role
        safe_delete "aws iam delete-role --role-name $BACKDOOR_ROLE" "Deleting backdoor role"
    fi
    
    # Clean up Lambda functions across regions
    if [ -n "$LAMBDA_FUNCTION" ]; then
        echo -e "${GREEN}[+] Cleaning up Lambda functions: $LAMBDA_FUNCTION${NC}"
        REGIONS=("us-west-2" "us-east-1" "us-east-2")
        
        for region in "${REGIONS[@]}"; do
            echo -e "  Cleaning up Lambda in region: $region"
            safe_delete "aws lambda delete-function --function-name $LAMBDA_FUNCTION --region $region" "Deleting Lambda function in $region"
        done
    fi
    
    # Clean up CloudWatch Events rule
    echo -e "${GREEN}[+] Cleaning up CloudWatch Events rule${NC}"
    safe_delete "aws events remove-targets --rule infrastructure-maintenance-schedule --ids 1" "Removing CloudWatch Events targets"
    safe_delete "aws events delete-rule --name infrastructure-maintenance-schedule" "Deleting CloudWatch Events rule"
    
    # Clean up SSM document
    if [ -n "$SSM_DOCUMENT" ]; then
        safe_delete "aws ssm delete-document --name $SSM_DOCUMENT" "Deleting SSM document $SSM_DOCUMENT"
    fi
    
    rm -f /tmp/cloud-infra-takeover-backdoor-user.txt
else
    echo -e "${YELLOW}[!] No persistence artifacts file found - skipping persistence cleanup${NC}"
fi

# 4. Clean up AWS CLI profiles created during the scenario
echo -e "\n${YELLOW}[*] Cleaning up temporary AWS CLI profiles${NC}"
PROFILES_TO_DELETE=("compromised" "escalated" "backdoor")

for profile in "${PROFILES_TO_DELETE[@]}"; do
    if aws configure list --profile $profile &>/dev/null; then
        echo -e "${GREEN}[+] Removing AWS CLI profile: $profile${NC}"
        
        # Remove profile sections from AWS config files
        aws configure --profile $profile list &>/dev/null
        if [ $? -eq 0 ]; then
            # Clear profile credentials
            aws configure set aws_access_key_id "" --profile $profile
            aws configure set aws_secret_access_key "" --profile $profile
            aws configure set aws_session_token "" --profile $profile
            aws configure set region "" --profile $profile
            
            echo -e "${GREEN}    ✓ Cleared profile: $profile${NC}"
        fi
    else
        echo -e "${YELLOW}    ! Profile $profile not found${NC}"
    fi
done

# 5. Clean up temporary files
echo -e "\n${YELLOW}[*] Cleaning up temporary files${NC}"
TEMP_FILES=(
    "/tmp/backdoor-access-key.txt"
    "/tmp/backdoor-secret-key.txt" 
    "/tmp/stolen-credentials.json"
)

for file in "${TEMP_FILES[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo -e "${GREEN}[+] Deleted temporary file: $file${NC}"
    fi
done

# 6. Final verification
echo -e "\n${YELLOW}[*] Final Verification${NC}"
echo -e "${GREEN}[+] Checking for remaining test resources...${NC}"

# Check for any remaining test resources by name patterns
echo -e "  Checking for test security groups..."
aws ec2 describe-security-groups --query 'SecurityGroups[?contains(GroupName, `test-attack-sg`)].GroupName' --output text 2>/dev/null | head -5 | sed 's/^/    Found: /' || echo "    None found"

echo -e "  Checking for test IAM policies..."
aws iam list-policies --query 'Policies[?contains(PolicyName, `TestAttackPolicy`)].PolicyName' --output text 2>/dev/null | head -5 | sed 's/^/    Found: /' || echo "    None found"

echo -e "  Checking for test S3 buckets..."
aws s3 ls 2>/dev/null | grep -E "(corp-infrastructure-logs|test-attack)" | sed 's/^/    Found: /' || echo "    None found"

echo -e "\n${GREEN}[+] ===============================================${NC}"
echo -e "${GREEN}[+] CLEANUP COMPLETE${NC}"
echo -e "${GREEN}[+] ===============================================${NC}"
echo -e "${YELLOW}[*] All test resources have been removed${NC}"
echo -e "${YELLOW}[*] AWS CLI profiles have been cleared${NC}"
echo -e "${YELLOW}[*] Temporary files have been deleted${NC}"
echo -e "\n${GREEN}[+] The Cloud Infrastructure Takeover test scenario cleanup is complete.${NC}"
echo -e "${YELLOW}[*] You may now safely run the scenario again or proceed with other tests.${NC}"