import boto3
import os

PANTHER_MASTER_REGION = os.environ['AWS_REGION']


def build_client(resource, service, region=None):
    """Function builds resource client that assumes Panther audit role"""
    account = resource['AccountId']
    role_arn = f'arn:aws:iam::{account}:role/PantherAuditRole-{PANTHER_MASTER_REGION}'
    sts_connection = boto3.client('sts')
    acct_b = sts_connection.assume_role(
        RoleArn=role_arn,
        RoleSessionName="lambda_assume_audit_role"
    )
    ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
    SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
    SESSION_TOKEN = acct_b['Credentials']['SessionToken']
    # create service client using the assumed role credentials, e.g. S3
    if region is None:
        client = boto3.client(
        service,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        )
    else:
        client = boto3.client(
        service,
        region,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        aws_session_token=SESSION_TOKEN,
        )
    return client