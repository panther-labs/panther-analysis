#!/bin/bash

# File: test_scenarios/aws-data-exfil/create_malicious_user.sh

# Check if AWS profile is provided as argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <aws-profile>"
    echo "Example: $0 homepage"
    exit 1
fi

# Set variables for the legitimate looking resources
USER_NAME="log-forwarder-svc"
AWS_PROFILE="$1"
S3_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonS3FullAccess"
EC2_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonEC2FullAccess"
IAM_ADMIN_POLICY="arn:aws:iam::aws:policy/IAMFullAccess"
SECRETS_MANAGER_ADMIN_POLICY="arn:aws:iam::aws:policy/SecretsManagerReadWrite"

echo "Creating test scenario: Malicious insider creating privileged data service account"

# Create what appears to be a service account
aws --profile $AWS_PROFILE iam create-user \
    --user-name $USER_NAME \
    --tags Key=Environment,Value=production Key=Team,Value=data-engineering Key=Purpose,Value=logging-automation

# Attach AWS-managed S3 admin policy
aws --profile $AWS_PROFILE iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $S3_ADMIN_POLICY

# Attach AWS-managed EC2 admin policy
aws --profile $AWS_PROFILE iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $EC2_ADMIN_POLICY

# Attach AWS-managed IAM admin policy
aws --profile $AWS_PROFILE iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $IAM_ADMIN_POLICY

# Attach AWS-managed Secrets Manager admin policy
aws --profile $AWS_PROFILE iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $SECRETS_MANAGER_ADMIN_POLICY

# Create access keys for programmatic access
aws --profile $AWS_PROFILE iam create-access-key \
    --user-name $USER_NAME

echo "Test scenario complete. Created user $USER_NAME with S3, EC2, and IAM admin access"
echo "This should trigger:"
echo "- aws_iam_create_user (signal)"
echo "- aws_iam_entity_created_without_cloudformation (alert)"
echo "- aws_iam_user_key_created (alert)"
