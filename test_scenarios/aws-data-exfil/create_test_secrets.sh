#!/bin/bash

# File: test_scenarios/aws-data-exfil/create_test_secrets.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if AWS profile is provided as argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <aws-profile>"
    echo "Example: $0 homepage"
    exit 1
fi

# Set variables
AWS_PROFILE="$1"
US_REGIONS=("us-east-1" "us-east-2" "us-west-1" "us-west-2")

echo "${YELLOW}[*] Creating test secrets for log forwarding and SIEM across US regions...${NC}"
echo "${YELLOW}[*] Using AWS profile: ${AWS_PROFILE}${NC}\n"

# Function to create a secret
create_secret() {
    local region="$1"
    local secret_name="$2"
    local secret_value="$3"
    local description="$4"
    
    echo "${GREEN}[+] Creating secret '$secret_name' in region $region...${NC}"
    
    # Create the secret
    aws --profile ${AWS_PROFILE} --region $region secretsmanager create-secret \
        --name "$secret_name" \
        --description "$description" \
        --secret-string "$secret_value" \
        --tags Key=Environment,Value=production Key=Team,Value=security Key=Purpose,Value=log-forwarding
    
    if [ $? -eq 0 ]; then
        echo "${GREEN}[+] Successfully created secret: $secret_name in $region${NC}"
    else
        echo "${RED}[!] Failed to create secret: $secret_name in $region${NC}"
    fi
}

# Create secrets in each region
for region in "${US_REGIONS[@]}"; do
    echo "${YELLOW}[*] Processing region: $region${NC}"
    
    # Secret 1: Log forwarding API credentials
    LOG_FORWARDING_SECRET='{
        "api_endpoint": "https://logs.panther.ai/api/v1/ingest",
        "api_key": "sk-1234567890abcdef1234567890abcdef12345678",
        "organization_id": "org_1234567890abcdef",
        "source_type": "aws_cloudtrail",
        "batch_size": 1000,
        "retry_attempts": 3,
        "compression": "gzip"
    }'
    
    create_secret "$region" "log-forwarder-api-credentials" "$LOG_FORWARDING_SECRET" "API credentials for log forwarding service"
    
    # Secret 2: SIEM integration credentials
    SIEM_SECRET='{
        "siem_endpoint": "https://panther.ai/api/events",
        "username": "log-forwarder-svc",
        "password": "P@ssw0rd!2024#Secure",
        "client_id": "siem-client-12345",
        "client_secret": "siem-secret-abcdef1234567890",
        "auth_url": "https://auth.company.com/oauth2/token",
        "log_level": "INFO",
        "timeout": 30
    }'
    
    create_secret "$region" "siem-integration-credentials" "$SIEM_SECRET" "SIEM integration credentials for security monitoring"
    
    echo ""
done

echo "${GREEN}[+] Test secret creation complete!${NC}"
echo "${YELLOW}[*] Created 2 secrets per region:${NC}"
echo "  - log-forwarder-api-credentials"
echo "  - siem-integration-credentials"
echo "${YELLOW}[*] Regions processed: ${US_REGIONS[*]}${NC}" 