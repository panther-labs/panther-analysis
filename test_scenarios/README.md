# Test Scenario 1 - Compromised AWS Root Credentials

## Usage

The script below is used to mimic real-life data consumption into Panther. It sends SQS messages for each line of the sample YAMLs.

```
$ python send_data.py --file <LOG_FILE>.yaml --account-id <AWS ACCOUNT ID> --queue-name <PANTHER QUEUE NAME> --region <REGION>
```

## Background Info

Legit IP: `71.253.251.71`
Attacker IP: `92.55.146.245`
Compromised Account: `493859302102`
Legit Employee: Tracey Stone
Attacker Alias: tracy stone (no e)
Malicious access key: AKIASWJJJ66ZZZII4IYY

## Usernames

tracy_stone (attacker)
tracey_stone (legit)
tracey.stone@acme.io

## Data

- AWS CloudTrail
- VPC Flow (network)
- Okta (show recon)
- S3 Server Access Logs (show exfiltration)

## Timeline

Date of compromise: 11/3/2020

- Failed Logins from Attacker (Okta)
- Legit Logins from team (CloudTrail)
- Failed logins from attacker (CloudTrail)
- Successful login from attacker (CloudTrail)
- Attacker creates a user and root access key (CloudTrail)
- Attacker spins up EC2s and Bucket
- Accessing customer data bucket
