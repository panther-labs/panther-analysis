#! /bin/bash

bucket=panther-test-scenario-7153027165
region=us-east-2

python send_data.py --region $region --compromise-datetime '2021-05-29T19:00:00+00:00' --bucket-name $bucket  --file okta-add-administrator/legit_login.yml
python send_data.py --region $region --compromise-datetime '2021-07-01T19:00:00+00:00' --bucket-name $bucket  --file okta-add-administrator/brute_force_logins.yml
python send_data.py --region $region --compromise-datetime '2021-07-02T19:00:00+00:00' --bucket-name $bucket  --file okta-add-administrator/new-user.yml
python send_data.py --region $region --compromise-datetime '2021-07-02T21:00:00+00:00' --bucket-name $bucket  --file okta-add-administrator/admin_privs_assigned.yml
