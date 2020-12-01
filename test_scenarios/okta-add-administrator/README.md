# Test Scenario - Okta Administrator

## Usage

Play the files in this order using the send_data.py script.

```bash
# Export some variables
$ export BUCKET=my-bucket
$ export AWSACCOUNTID=123456789012
$ export AWS_REGION=us-east-1
# Send the sample data
$ python send_data.py --account-id $AWSACCOUNTID --region $AWS_REGION --compromise-datetime '2020-11-30T18:34:12+00:00' --bucket-name $BUCKET  --file okta-add-administrator/legit_login.yml
$ python send_data.py --account-id $AWSACCOUNTID --region $AWS_REGION --compromise-datetime '2020-12-01T18:34:12+00:00' --bucket-name $BUCKET  --file okta-add-administrator/brute_force_logins.yml
$ python send_data.py --account-id $AWSACCOUNTID --region $AWS_REGION --compromise-datetime '2020-12-01T19:11:42+00:00' --bucket-name $BUCKET  --file okta-add-administrator/admin_privs_assigned.yml
```

## Background Info

This scenario shows brute force logins

## Usernames

jack.naglieri@tines.io
thomas.kinsella@tines.io

## Data

- Okta.SystemLog
