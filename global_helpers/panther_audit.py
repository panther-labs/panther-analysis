import os
import boto3

PANTHER_MASTER_REGION = os.environ.get('AWS_REGION')


def build_client(resource, service, region=None):
    """Function builds resource client that assumes Panther audit role"""
    account = resource['AccountId']
    role_arn = f'arn:aws:iam::{account}:role/PantherAuditRole-{PANTHER_MASTER_REGION}'
    sts_connection = boto3.client('sts')
    acct_b = sts_connection.assume_role(
        RoleArn=role_arn, RoleSessionName="lambda_assume_audit_role")
    access_key = acct_b['Credentials']['AccessKeyId']
    secret_key = acct_b['Credentials']['SecretAccessKey']
    session_token = acct_b['Credentials']['SessionToken']
    # create service client using the assumed role credentials, e.g. S3
    if region is None:
        client = boto3.client(
            service,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
    else:
        client = boto3.client(
            service,
            region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
    return client
