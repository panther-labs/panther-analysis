# Test Scenario - Compromised AWS Root Credentials

## Usage

Play the files in this order using the send_data.py script.

```python

python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/victim_okta.yml 
python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/victim_cloudtrail.yml 
python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/attacker_okta.yml 
python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/attacker_cloudtrail.yml
python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/attacker_s3_access.yml 
python send_data.py --account-id 050603629XXX --region us-east-1 --compromise-datetime '2020-11-01T18:00:00+00:00' --bucket-name my-panther-demo  --file compromised-root-creds/attacker_vpc.yml 

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

Date of compromise: 11/01/2020

- 10/26/2020: Failed Logins from attacker (Okta) 
- 10/27/2020: Legit Logins from team (CloudTrail) 
- 10/30/2020: Failed logins from attacker (CloudTrail) 
- 11/01/2020: Successful login from attacker (CloudTrail) 
- 11/01/2020: Attacker creates a user and root access key (CloudTrail)
- 11/01/2020: Attacker spins up EC2s and Bucket, Stops CloudTrail (CloudTrail) 
- 11/01/2020: Accessing customer data bucket (S3 Access Logs) 
- 11/01/2020: Attacker uses EC2 instance to exfil data (VPC Flow) 

Last timestamp: 2020-11-01T18:01:00+00:00

