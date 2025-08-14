#!/bin/bash

# File: test_scenarios/aws-data-exfil/update_test_secrets.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Set variables
US_REGIONS=("us-east-1" "us-east-2" "us-west-1" "us-west-2")

echo "${YELLOW}[*] Updating test secrets for log forwarding and SIEM across US regions...${NC}"

# Function to update a secret
update_secret() {
    local region="$1"
    local secret_name="$2"
    local secret_value="$3"
    
    echo "${GREEN}[+] Updating secret '$secret_name' in region $region...${NC}"
    
    # Update the secret
    aws --region $region secretsmanager update-secret \
        --secret-id "$secret_name" \
        --secret-string "$secret_value"
    
    if [ $? -eq 0 ]; then
        echo "${GREEN}[+] Successfully updated secret: $secret_name in $region${NC}"
    else
        echo "${RED}[!] Failed to update secret: $secret_name in $region${NC}"
    fi
}

# Update secrets in each region
for region in "${US_REGIONS[@]}"; do
    echo "${YELLOW}[*] Processing region: $region${NC}"
    
    # Secret 1: Log forwarding API credentials
    LOG_FORWARDING_SECRET='{
        "api_endpoint": "test-endpoint",
        "api_key": "test-key",
        "organization_id": "test-org",
        "batch_size": 100,
        "retry_attempts": 3,
        "compression": "gzip",
        "source_type": "aws_cloudtrail"
    }'
    
    update_secret "$region" "log-forwarder-api-credentials" "$LOG_FORWARDING_SECRET"
    
    # Secret 2: SIEM integration credentials
    SIEM_SECRET='{
        "siem_endpoint": "test-endpoint",
        "token": "test-token"
    }'
    
    update_secret "$region" "siem-integration-credentials" "$SIEM_SECRET"
    
    echo ""
done

echo "${GREEN}[+] Test secret update complete!${NC}"
echo "${YELLOW}[*] Updated 2 secrets per region:${NC}"
echo "  - log-forwarder-api-credentials"
echo "  - siem-integration-credentials"
echo "${YELLOW}[*] Regions processed: ${US_REGIONS[*]}${NC}"