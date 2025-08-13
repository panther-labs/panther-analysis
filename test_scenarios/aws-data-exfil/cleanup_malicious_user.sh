#!/bin/bash

# File: test_scenarios/aws-data-exfil/cleanup_malicious_user.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set variables for the resources to clean up
USER_NAME="log-forwarder-svc"
S3_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonS3FullAccess"
EC2_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonEC2FullAccess"
IAM_ADMIN_POLICY="arn:aws:iam::aws:policy/IAMFullAccess"
SECRETS_MANAGER_ADMIN_POLICY="arn:aws:iam::aws:policy/SecretsManagerReadWrite"

echo "${YELLOW}[*] Cleaning up test scenario: Removing user $USER_NAME and associated resources using default AWS profile${NC}"

# Detach the S3 admin policy
echo "${GREEN}[+] Detaching S3 admin policy from $USER_NAME...${NC}"
aws iam detach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $S3_ADMIN_POLICY

# Detach the EC2 admin policy
echo "${GREEN}[+] Detaching EC2 admin policy from $USER_NAME...${NC}"
aws iam detach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $EC2_ADMIN_POLICY

# Detach the IAM admin policy
echo "${GREEN}[+] Detaching IAM admin policy from $USER_NAME...${NC}"
aws iam detach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $IAM_ADMIN_POLICY

# Detach the Secrets Manager admin policy
echo "${GREEN}[+] Detaching Secrets Manager admin policy from $USER_NAME...${NC}"
aws iam detach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $SECRETS_MANAGER_ADMIN_POLICY

# Delete all access keys for the user
echo "${GREEN}[+] Deleting all access keys for $USER_NAME...${NC}"
ACCESS_KEYS=$(aws iam list-access-keys --user-name $USER_NAME --query 'AccessKeyMetadata[].AccessKeyId' --output text)
for key in $ACCESS_KEYS; do
    echo "${YELLOW}[*] Deleting access key $key for user $USER_NAME${NC}"
    aws iam delete-access-key --user-name $USER_NAME --access-key-id $key
done

# Delete the user
echo "${GREEN}[+] Deleting user $USER_NAME...${NC}"
aws iam delete-user --user-name $USER_NAME

echo "\n${YELLOW}[*] Cleanup complete. User $USER_NAME and associated resources have been removed.${NC}" 