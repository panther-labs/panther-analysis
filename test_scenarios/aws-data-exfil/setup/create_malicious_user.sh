#!/bin/bash

# Set variables for the legitimate looking resources
USER_NAME="backup-service-account"
EC2_ADMIN_POLICY="arn:aws:iam::aws:policy/AmazonEC2FullAccess"
SECRETS_MANAGER_ADMIN_POLICY="arn:aws:iam::aws:policy/SecretsManagerReadWrite"

echo "Creating test scenario: Malicious insider creating privileged data service account"

# Create what appears to be a service account
aws iam create-user \
    --user-name $USER_NAME \
    --tags Key=Environment,Value=production Key=Team,Value=data-engineering Key=Purpose,Value=backup-service-account

# Create custom S3 policy for jn-* buckets only
S3_POLICY_DOC='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
                "s3:GetBucketVersioning",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketTagging"
            ],
            "Resource": "arn:aws:s3:::jn-*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:GetObjectAcl",
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
            ],
            "Resource": "arn:aws:s3:::jn-*/*"
        }
    ]
}'

# Attach custom S3 policy for jn-* buckets
aws iam put-user-policy \
    --user-name $USER_NAME \
    --policy-name "JNBucketsAccess" \
    --policy-document "$S3_POLICY_DOC"

# Attach AWS-managed EC2 admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $EC2_ADMIN_POLICY

# Attach AWS-managed Secrets Manager admin policy
aws iam attach-user-policy \
    --user-name $USER_NAME \
    --policy-arn $SECRETS_MANAGER_ADMIN_POLICY

# Create access keys for programmatic access
aws iam create-access-key \
    --user-name $USER_NAME

echo "Test scenario complete. Created user $USER_NAME with jn-* S3 bucket access, EC2, and Secrets Manager admin access"
