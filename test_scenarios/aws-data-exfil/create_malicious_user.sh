#!/bin/bash

# File: test_scenarios/aws-data-exfil/create_malicious_user.sh

# Set variables for the legitimate looking resources
USER_NAME="backup-service-account"
S3_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonS3FullAccess"
EC2_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonEC2FullAccess"
SECRETS_MANAGER_ADMIN_POLICY="arn:aws:iam::aws:policy/SecretsManagerReadWrite"

echo "Creating test scenario: Malicious insider creating privileged data service account"

# Create what appears to be a service account
aws iam create-user \
    --user-name $USER_NAME \
    --tags Key=Environment,Value=production Key=Team,Value=data-engineering Key=Purpose,Value=backup-service-account

# Attach AWS-managed S3 admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $S3_ADMIN_POLICY

# Attach AWS-managed EC2 admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $EC2_ADMIN_POLICY

# Attach AWS-managed IAM admin policy
# aws iam attach-user-policy \
#     --user-name $USER_NAME \
#     --policy-arn $IAM_ADMIN_POLICY

# Attach AWS-managed Secrets Manager admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $SECRETS_MANAGER_ADMIN_POLICY

# Create access keys for programmatic access
aws iam create-access-key \
    --user-name $USER_NAME

echo "Test scenario complete. Created user $USER_NAME with S3, EC2, and IAM admin access"
