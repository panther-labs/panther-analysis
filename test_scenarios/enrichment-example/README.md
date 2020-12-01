# Test Scenario - Data Enrichment with Tines

## Usage

This CloudTrail log is an example used for enrichment and feedback into Panther.

```bash
# Export some variables
$ export BUCKET=my-bucket
$ export AWSACCOUNTID=123456789012
$ export AWS_REGION=us-east-1
# Send the sample data
$ python send_data.py --account-id $AWSACCOUNTID --region $AWS_REGION --compromise-datetime '2020-11-30T18:34:12+00:00' --bucket-name $BUCKET  --file enrichment-example/attacker_cloudtrail.yml
```

## Background Info

These CloudTrail logs show failed logins, followed by a successful one, followed by some actions. The user IP is from a known malware list, which triggers findings in Threat Intel lookups.

## Usernames

N/A

## Data

- AWS.CloudTrail
