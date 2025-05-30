#!/bin/bash

# File: test_scenarios/aws-data-exfil/create_malicious_user.sh

# Set variables for the "legitimate looking" resources
USER_NAME="security-tools-svc"
S3_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonS3FullAccess"

echo "Creating test scenario: Malicious insider creating privileged data service account"

# Create what appears to be a service account
aws iam create-user \
    --user-name $USER_NAME \
    --tags Key=Environment,Value=production Key=Team,Value=data-engineering Key=Purpose,Value=etl-automation

# Attach AWS-managed S3 admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $S3_ADMIN_POLICY

# Create access keys for programmatic access
aws iam create-access-key \
    --user-name $USER_NAME

echo "Test scenario complete. Created user $USER_NAME with S3 admin access"
echo "This should trigger:"
echo "- aws_iam_create_user (signal)"
echo "- aws_iam_entity_created_without_cloudformation (alert)"
echo "- aws_iam_user_key_created (alert)"
