## AWS ACM

- [AWS ACM Certificate Expiration](../policies/aws_acm_policies/aws_acm_certificate_expiration.yml)
  - When a certificate is 60 days away from expiration, ACM automatically attempts to renew it every hour.
- [AWS ACM Certificate Status](../policies/aws_acm_policies/aws_acm_certificate_valid.yml)
  - This policy checks if an ACM certificate renewal is pending or has failed and is in use by any other resources within the account.
- [AWS ACM Secure Algorithms](../policies/aws_acm_policies/aws_acm_certificate_has_secure_algorithms.yml)
  - This policy validates that all ACM certificates are using secure key and signature algorithms.


## AWS CloudFormation

- [AWS CloudFormation Stack Drift](../policies/aws_cloudformation_policies/aws_cloudformation_stack_drifted.yml)
  - A stack has drifted from its defined configuration.
- [AWS CloudFormation Stack IAM Service Role](../policies/aws_cloudformation_policies/aws_cloudformation_stack_uses_iam_role.yml)
  - Associating IAM roles with CloudFormation stacks ensures least privilege when making changes to your account.
- [AWS CloudFormation Stack Termination Protection](../policies/aws_cloudformation_policies/aws_cloudformation_termination_protection.yml)
  - Protects a CloudFormation stack from accidentally being deleted. If you attempt to delete a stack with termination protection enabled, the deletion fails and the stack, including its status, will remain unchanged.


## AWS CloudTrail

- [A CloudTrail Was Created or Updated](../rules/aws_cloudtrail_rules/aws_cloudtrail_created.yml)
  - A CloudTrail Trail was created, updated, or enabled.
- [Account Security Configuration Changed](../rules/aws_cloudtrail_rules/aws_security_configuration_change.yml)
  - An account wide security configuration was changed.
- [Amazon Machine Image (AMI) Modified to Allow Public Access](../rules/aws_cloudtrail_rules/aws_ami_modified_for_public_access.yml)
  - An Amazon Machine Image (AMI) was modified to allow it to be launched by anyone. Any sensitive configuration or application data stored in the AMI's block devices is at risk.
- [Anomalous AccessDenied Requests](../queries/aws_queries/anomalous_access_denied_query.yml)
  - ARNs with a high Access Denied error rate could indicate an error or compromised credentials attempting to perform reconnaissance.
- [AWS Access Key Uploaded to Github](../rules/aws_cloudtrail_rules/aws_key_compromised.yml)
  - A users static AWS API key was uploaded to a public github repo.
- [AWS Authentication from CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_Query.yml)
  - Detects AWS Authentication events with IP Addresses not found in CrowdStrike's AIP List
- [AWS Authentication from CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/aws_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_FDREvent.yml)
  - Detects AWS Authentication events with IP Addresses not found in CrowdStrike's AIP List
- [AWS Backdoor Administrative IAM Role Created](../correlation_rules/aws_create_backdoor_admin_iam_role.yml)
  - Identifies when CreateRole and AttachAdminRolePolicy CloudTrail events occur in a short period of time. This sequence could indicate a potential security breach.
- [AWS Bedrock Guardrail Updated or Deleted](../rules/aws_cloudtrail_rules/aws_bedrock_guardrail_update_delete.yml)
  - An Amazon Bedrock Guardrail was updated or deleted. Amazon Bedrock Guardrails are used to implement application-specific safeguards based on your use cases and responsible AI policies. Updating or deleting a guardrail can have security implications to your AI workloads.
- [AWS Bedrock Model Invocation Logging Configuration Deleted](../rules/aws_cloudtrail_rules/aws_bedrock_deletemodelinvocationloggingconfiguration.yml)
  - An Amazon Bedrock Model Invocation Logging Configuration was deleted. Use model invocation logging to collect metadata, requests, and responses for all model invocations in your account. Deleting a model invocation logging configuration can have security implications to your AI workloads.
- [AWS CloudTrail Account Discovery](../rules/aws_cloudtrail_rules/aws_cloudtrail_account_discovery.yml)
  - Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.
- [AWS CloudTrail Attempt To Leave Org](../rules/aws_cloudtrail_rules/aws_cloudtrail_attempt_to_leave_org.yml)
  - Detects when an actor attempts to remove an AWS account from an Organization. Security configurations are often defined at the organizational level. Leaving the organization can disrupt or totally shut down these controls.
- [AWS CloudTrail CloudWatch Logs](../policies/aws_cloudtrail_policies/aws_cloudtrail_cloudwatch_logs.yml)
  - CloudTrail supports sending data and management events to CloudWatch Logs. This setup can be used for real-time processing of all CloudTrail data events.
- [AWS CloudTrail Log Encryption](../policies/aws_cloudtrail_policies/aws_cloudtrail_log_encryption.yml)
  - This policy validates that CloudTrail Logs are encrypted at rest with customer managed KMS key.
- [AWS CloudTrail Log Validation](../policies/aws_cloudtrail_policies/aws_cloudtrail_log_validation.yml)
  - This policy ensures that CloudTrail logs have file integrity validation enabled.
- [AWS CloudTrail Management Events Enabled](../policies/aws_cloudtrail_policies/aws_cloudtrail_enabled.yml)
  - This policy ensures that at least one CloudTrail has management (control plane) operations logged.
- [AWS CloudTrail Password Policy Discovery](../rules/aws_cloudtrail_rules/aws_cloudtrail_password_policy_discovery.yml)
  - This detection looks for *AccountPasswordPolicy events in AWS CloudTrail logs. If these events occur in a short period of time from the same ARN, it could constitute Password Policy reconnaissance.
- [AWS CloudTrail Retention Lifecycle Too Short](../rules/aws_cloudtrail_rules/aws_cloudtrail_short_lifecycle.yml)
  - Detects when an S3 bucket containing CloudTrail logs has been modified to delete data after a short period of time.
- [AWS CloudTrail S3 Bucket Access Logging](../policies/aws_cloudtrail_policies/aws_cloudtrail_s3_bucket_access_logging.yml)
  - This policy validates that the bucket receiving CloudTrail Logs is configured with S3 Access Logging. This audits all creation, modification, or deletion to CloudTrail audit logs.
- [AWS CloudTrail S3 Bucket Public](../policies/aws_cloudtrail_policies/aws_cloudtrail_s3_bucket_public.yml)
  - This policy validates that CloudTrail S3 buckets are not publicly accessible.
- [AWS CloudTrail SES Check Identity Verifications](../rules/aws_cloudtrail_rules/aws_cloudtrail_ses_check_identity_verifications.yml)
- [AWS CloudTrail SES Check Send Quota](../rules/aws_cloudtrail_rules/aws_cloudtrail_ses_check_send_quota.yml)
  - Detect when someone checks how many emails can be delivered via SES
- [AWS CloudTrail SES Check SES Sending Enabled](../rules/aws_cloudtrail_rules/aws_cloudtrail_ses_check_ses_sending_enabled.yml)
  - Detect when a user inquires whether SES Sending is enabled.
- [AWS CloudTrail SES Enumeration](../rules/aws_cloudtrail_rules/aws_cloudtrail_ses_enumeration.yml)
- [AWS CloudTrail SES List Identities](../rules/aws_cloudtrail_rules/aws_cloudtrail_ses_list_identities.yml)
- [AWS Compromised IAM Key Quarantine](../rules/aws_cloudtrail_rules/aws_iam_compromised_key_quarantine.yml)
  - Detects when an IAM user has the AWSCompromisedKeyQuarantineV2 policy attached to their account.
- [AWS Config Service Created](../rules/aws_cloudtrail_rules/aws_config_service_created.yml)
  - An AWS Config Recorder or Delivery Channel was created
- [AWS Config Service Disabled](../rules/aws_cloudtrail_rules/aws_config_service_disabled_deleted.yml)
  - An AWS Config Recorder or Delivery Channel was disabled or deleted
- [AWS Console Login](../rules/aws_cloudtrail_rules/aws_console_login.yml)
- [AWS Console Sign-In NOT PRECEDED BY Okta Redirect](../correlation_rules/aws_console_sign-in_without_okta.yml)
  - A user has logged into the AWS console without authenticating via Okta.  This rule requires AWS SSO via Okta and both log sources configured.
- [AWS DNS Logs Deleted](../rules/aws_cloudtrail_rules/aws_dns_logs_deleted.yml)
  - Detects when logs for a DNS Resolver have been removed.
- [AWS EC2 Discovery Commands Executed](../queries/aws_queries/ec2_discovery_commands_query.yml)
  - Multiple different discovery commands were executed by the same EC2 instance.
- [AWS EC2 Download Instance User Data](../rules/aws_cloudtrail_rules/aws_ec2_download_instance_user_data.yml)
  - An entity has accessed the user data scripts of multiple EC2 instances.
- [AWS EC2 EBS Encryption Disabled](../rules/aws_cloudtrail_rules/aws_ec2_ebs_encryption_disabled.yml)
  - Identifies disabling of default EBS encryption. Disabling default encryption does not change the encryption status of existing volumes.
- [AWS EC2 Image Monitoring](../rules/aws_cloudtrail_rules/aws_ec2_monitoring.yml)
  - Checks CloudTrail for occurrences of EC2 Image Actions.
- [AWS EC2 Launch Unusual EC2 Instances](../rules/aws_cloudtrail_rules/aws_ec2_launch_unusual_ec2_instances.yml)
  - Detect when an actor deploys an EC2 instance with an unusual profile based on your business needs.
- [AWS EC2 Manual Security Group Change](../rules/aws_cloudtrail_rules/aws_ec2_manual_security_group_changes.yml)
  - An EC2 security group was manually updated without abiding by the organization's accepted processes. This rule expects organizations to either use the Console, CloudFormation, or Terraform, configurable in the rule's ALLOWED_USER_AGENTS.
- [AWS EC2 Many Password Read Attempts](../rules/aws_cloudtrail_rules/aws_ec2_many_passwors_read_attempts.yml)
  - An actor in AWS has made many attempts to retrieve EC2 passwords. It is typically not necessary to retrieve EC2 passwords more than a few times an hour.
- [AWS EC2 Multi Instance Connect](../rules/aws_cloudtrail_rules/aws_ec2_multi_instance_connect.yml)
  - Detect when an attacker pushes an SSH public key to multiple EC2 instances.
- [AWS EC2 Startup Script Change](../rules/aws_cloudtrail_rules/aws_ec2_startup_script_change.yml)
  - Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.
- [AWS EC2 Traffic Mirroring](../rules/aws_cloudtrail_rules/aws_ec2_traffic_mirroring.yml)
  - This rule captures multiple traffic mirroring events in AWS Cloudtrail.
- [AWS EC2 Vulnerable XZ Image Launched](../rules/aws_cloudtrail_rules/aws_ec2_vulnerable_xz_image_launched.yml)
  - Detecting EC2 instances launched with AMIs containing potentially vulnerable versions of XZ (CVE-2024-3094)
- [AWS ECR Events](../rules/aws_cloudtrail_rules/aws_ecr_events.yml)
  - An ECR event occurred outside of an expected account or region
- [AWS IAM Group Read Only Events](../rules/aws_cloudtrail_rules/aws_iam_group_read_only_events.yml)
  - This rule captures multiple read/list events related to IAM group management in AWS Cloudtrail.
- [AWS Macie Disabled/Updated](../rules/aws_cloudtrail_rules/aws_macie_evasion.yml)
  - Amazon Macie is a data security and data privacy service to discover and protect sensitive data. Security teams use Macie to detect open S3 Buckets that could have potentially sensitive data in it along with policy violations, such as missing Encryption. If an attacker disables Macie, it could potentially hide data exfiltration.
- [AWS Modify Cloud Compute Infrastructure](../rules/aws_cloudtrail_rules/aws_modify_cloud_compute_infrastructure.yml)
  - Detection when EC2 compute infrastructure is modified outside of expected automation methods.
- [AWS Network ACL Overly Permissive Entry Created](../rules/aws_cloudtrail_rules/aws_network_acl_permissive_entry.yml)
  - A Network ACL entry that allows access from anywhere was added.
- [AWS Potential Backdoor Lambda Function Through Resource-Based Policy](../rules/aws_cloudtrail_rules/aws_backdoor_lambda_function.yml)
  - Identifies when a permission is added to a Lambda function, which could indicate a potential security risk.
- [AWS Potentially Stolen Service Role](../queries/aws_queries/aws_potentially_compromised_service_role_query.yml)
  - A role was assumed by an AWS service, followed by a user within 24 hours.  This could indicate a stolen or compromised AWS service role.
- [AWS Privilege Escalation Via User Compromise](../correlation_rules/aws_privilege_escalation_via_user_compromise.yml)
- [AWS Public RDS Restore](../rules/aws_cloudtrail_rules/aws_rds_publicrestore.yml)
  - Detects the recovery of a new public database instance from a snapshot. It may be part of data exfiltration.
- [AWS RDS Manual/Public Snapshot Created](../rules/aws_cloudtrail_rules/aws_rds_manual_snapshot_created.yml)
  - A manual snapshot of an RDS database was created. An attacker may use this to exfiltrate the DB contents to another account; use this as a correlation rule.
- [AWS RDS Master Password Updated](../rules/aws_cloudtrail_rules/aws_rds_master_pass_updated.yml)
  - A sensitive database operation that should be performed carefully or rarely
- [AWS RDS Snapshot Shared](../rules/aws_cloudtrail_rules/aws_rds_snapshot_shared.yml)
  - An RDS snapshot was shared with another account. This could be an indicator of exfiltration.
- [AWS Resource Made Public](../rules/aws_cloudtrail_rules/aws_resource_made_public.yml)
  - Some AWS resource was made publicly accessible over the internet. Checks ECR, Elasticsearch, KMS, S3, S3 Glacier, SNS, SQS, and Secrets Manager.
- [AWS S3 Bucket Policy Modified](../rules/aws_cloudtrail_rules/aws_s3_bucket_policy_modified.yml)
  - An S3 Bucket was modified.
- [AWS SAML Activity](../rules/aws_cloudtrail_rules/aws_saml_activity.yml)
  - Identifies when SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.
- [AWS Secrets Manager Batch Retrieve Secrets](../rules/aws_cloudtrail_rules/aws_secretsmanager_retrieve_secrets_batch.yml)
  - An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets.
- [AWS Secrets Manager Batch Retrieve Secrets Catch-All](../rules/aws_cloudtrail_rules/aws_secretsmanager_retrieve_secrets_catchall.yml)
  - An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets. Although BatchGetSecretValue requires a list of secret IDs or a filter, an attacker may use a catch-all filter to retrieve all secrets by batch. This rule identifies BatchGetSecretValue events with a catch-all filter.
- [AWS Secrets Manager Retrieve Secrets Multi-Region](../rules/aws_cloudtrail_rules/aws_secretsmanager_retrieve_secrets_multiregion.yml)
  - An attacker attempted to retrieve a high number of Secrets Manager secrets by batch, through secretsmanager:BatchGetSecretValue (released Novemeber 2023).  An attacker may attempt to retrieve a high number of secrets by batch, to avoid detection and generate fewer calls. Note that the batch size is limited to 20 secrets. This rule identifies BatchGetSecretValue events for multiple regions in a short period of time.
- [AWS SecurityHub Finding Evasion](../rules/aws_cloudtrail_rules/aws_securityhub_finding_evasion.yml)
  - Detections modification of findings in SecurityHub
- [AWS Snapshot Made Public](../rules/aws_cloudtrail_rules/aws_snapshot_made_public.yml)
  - An AWS storage snapshot was made public.
- [AWS Software Discovery](../rules/aws_cloudtrail_rules/aws_software_discovery.yml)
  - A user is obtaining a list of security software, configurations, defensive tools, and sensors that are in AWS.
- [AWS SSO Access Token Retrieved by Unauthenticated IP](../correlation_rules/aws_sso_access_token_retrieved_by_unauthenticated_ip.yml)
  - When using AWS in an enterprise environment, best practices dictate to use a single sign-on service for identity and access management. AWS SSO is a popular solution, integrating with third-party providers such as Okta and allowing to centrally manage roles and permissions in multiple AWS accounts.In this post, we demonstrate that AWS SSO is vulnerable by design to device code authentication phishing – just like any identity provider implementing OpenID Connect device code authentication. This technique was first demonstrated by Dr. Nestori Syynimaa for Azure AD. The feature provides a powerful phishing vector for attackers, rendering ineffective controls such as MFA (including Yubikeys) or IP allow-listing at the IdP level.
- [AWS Trusted IPSet Modified](../rules/aws_cloudtrail_rules/aws_ipset_modified.yml)
  - Detects creation and updates of the list of trusted IPs used by GuardDuty and WAF. Potentially to disable security alerts against malicious IPs.
- [AWS Unsuccessful MFA attempt](../rules/aws_cloudtrail_rules/aws_cloudtrail_unsuccessful_mfa_attempt.yml)
  - Monitor application logs for suspicious events including repeated MFA failures that may indicate user's primary credentials have been compromised.
- [AWS User API Key Created](../rules/aws_cloudtrail_rules/aws_iam_user_key_created.yml)
  - Detects AWS API key creation for a user by another user. Backdoored users can be used to obtain persistence in the AWS environment.
- [AWS User Login Profile Created or Modified](../rules/aws_cloudtrail_rules/aws_cloudtrail_loginprofilecreatedormodified.yml)
  - An attacker with iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console. May be legitimate account administration.
- [AWS User Takeover Via Password Reset](../correlation_rules/aws_user_takeover_via_password_reset.yml)
- [AWS VPC Flow Logs Removed](../rules/aws_cloudtrail_rules/aws_vpc_flow_logs_deleted.yml)
  - Detects when logs for a VPC have been removed.
- [AWS WAF Disassociation](../rules/aws_cloudtrail_rules/aws_waf_disassociation.yml)
  - Detection to alert when a WAF disassociates from a source.
- [AWS.Administrative.IAM.User.Created](../correlation_rules/aws_create_admin_iam_user.yml)
  - Identifies when an Administrative IAM user is creates. This could indicate a potential security breach.
- [AWS.CloudTrail.UserAccessKeyAuth](../rules/aws_cloudtrail_rules/aws_cloudtrail_useraccesskeyauth.yml)
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [CloudTrail EC2 StopInstances](../rules/aws_cloudtrail_rules/aws_ec2_stopinstances.yml)
  - A CloudTrail instances were stopped. It makes further changes of instances possible
- [CloudTrail Event Selectors Disabled](../rules/aws_cloudtrail_rules/aws_cloudtrail_event_selectors_disabled.yml)
  - A CloudTrail Trail was modified to exclude management events for 1 or more resource types.
- [CloudTrail Password Spraying](../queries/aws_queries/cloudtrail_password_spraying.yml)
  - Detect password spraying account using a scheduled query
- [CloudTrail Stopped](../rules/aws_cloudtrail_rules/aws_cloudtrail_stopped.yml)
  - A CloudTrail Trail was modified.
- [CodeBuild Project made Public](../rules/aws_cloudtrail_rules/aws_codebuild_made_public.yml)
  - An AWS CodeBuild Project was made publicly accessible
- [Detect Reconnaissance from IAM Users](../rules/aws_cloudtrail_rules/aws_iam_user_recon_denied.yml)
  - An IAM user has a high volume of access denied API calls.
- [EC2 Network ACL Modified](../rules/aws_cloudtrail_rules/aws_ec2_network_acl_modified.yml)
  - An EC2 Network ACL was modified.
- [EC2 Network Gateway Modified](../rules/aws_cloudtrail_rules/aws_ec2_gateway_modified.yml)
  - An EC2 Network Gateway was modified.
- [EC2 Route Table Modified](../rules/aws_cloudtrail_rules/aws_ec2_route_table_modified.yml)
  - An EC2 Route Table was modified.
- [EC2 Secrets Manager Retrieve Secrets](../rules/aws_cloudtrail_rules/aws_secretsmanager_retrieve_secrets.yml)
  - An attacker attempted to retrieve a high number of Secrets Manager secrets, through secretsmanager:GetSecretValue.
- [EC2 Security Group Modified](../rules/aws_cloudtrail_rules/aws_ec2_security_group_modified.yml)
  - An EC2 Security Group was modified.
- [EC2 VPC Modified](../rules/aws_cloudtrail_rules/aws_ec2_vpc_modified.yml)
  - An EC2 VPC was modified.
- [ECR CRUD Actions](../rules/aws_cloudtrail_rules/aws_ecr_crud.yml)
  - Unauthorized ECR Create, Read, Update, or Delete event occurred.
- [Failed Root Console Login](../rules/aws_cloudtrail_rules/aws_console_root_login_failed.yml)
  - A Root console login failed.
- [IAM Administrator Role Policy Attached](../rules/aws_cloudtrail_rules/aws_iam_attach_admin_role_policy.yml)
  - An IAM role policy was attached with Administrator Access, which could indicate a potential security risk.
- [IAM Assume Role Blocklist Ignored](../rules/aws_cloudtrail_rules/aws_iam_assume_role_blocklist_ignored.yml)
  - A user assumed a role that was explicitly blocklisted for manual user assumption.
- [IAM Change](../rules/aws_cloudtrail_rules/aws_iam_anything_changed.yml)
  - A change occurred in the IAM configuration. This could be a resource being created, deleted, or modified. This is a high level view of changes, helfpul to indicate how dynamic a certain IAM environment is.
- [IAM Entity Created Without CloudFormation](../rules/aws_cloudtrail_rules/aws_iam_entity_created_without_cloudformation.yml)
  - An IAM Entity (Group, Policy, Role, or User) was created manually. IAM entities should be created in code to ensure that permissions are tracked and managed correctly.
- [IAM Policy Modified](../rules/aws_cloudtrail_rules/aws_iam_policy_modified.yml)
  - An IAM Policy was changed.
- [IAM Role Created](../rules/aws_cloudtrail_rules/aws_iam_create_role.yml)
  - An IAM role was created.
- [IAM Role Policy Updated to Allow Internet Access](../rules/aws_cloudtrail_rules/aws_iam_backdoor_role.yml)
  - An IAM role policy was updated to allow internet access, which could indicate a backdoor.
- [IAM User Created](../rules/aws_cloudtrail_rules/aws_iam_create_user.yml)
  - An IAM user was created, which could indicate a new user creation or policy update.
- [IAM User Policy Attached with Administrator Access](../rules/aws_cloudtrail_rules/aws_iam_attach_admin_user_policy.yml)
  - An IAM user policy was attached with Administrator Access, which could indicate a potential security risk.
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
  - A user has subsequent logins from two geographic locations that are very far apart
- [KMS CMK Disabled or Deleted](../rules/aws_cloudtrail_rules/aws_kms_cmk_loss.yml)
  - A KMS Customer Managed Key was disabled or scheduled for deletion. This could potentially lead to permanent loss of encrypted data.
- [Lambda CRUD Actions](../rules/aws_cloudtrail_rules/aws_lambda_crud.yml)
  - Unauthorized lambda Create, Read, Update, or Delete event occurred.
- [Lambda Update Function Code](../rules/aws_cloudtrail_rules/aws_overwrite_lambda_code.yml)
  - Identifies when the code of a Lambda function is updated, which could indicate a potential security risk.
- [Lambda Update Function Configuration with Layers](../rules/aws_cloudtrail_rules/aws_add_malicious_lambda_extension.yml)
  - Identifies when a Lambda function configuration is updated with layers, which could indicate a potential security risk.
- [Logins Without MFA](../rules/aws_cloudtrail_rules/aws_console_login_without_mfa.yml)
  - A console login was made without multi-factor authentication.
- [Logins Without SAML](../rules/aws_cloudtrail_rules/aws_console_login_without_saml.yml)
  - An AWS console login was made without SAML/SSO.
- [Monitor Unauthorized API Calls](../rules/aws_cloudtrail_rules/aws_unauthorized_api_call.yml)
  - An unauthorized AWS API call was made
- [New AWS Account Created](../rules/indicator_creation_rules/new_aws_account_logging.yml)
  - A new AWS account was created
- [New IAM Credentials Updated](../rules/aws_cloudtrail_rules/aws_update_credentials.yml)
  - A console password, access key, or user has been created.
- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
  - A new account was created
- [RoleAssumes by Multiple Useragents](../queries/aws_queries/anomalous_role_assume_query.yml)
  - RoleAssumes with multiple Useragents could indicate compromised credentials.
- [Root Account Access Key Created](../rules/aws_cloudtrail_rules/aws_root_access_key_created.yml)
  - An access key was created for the Root account
- [Root Account Activity](../rules/aws_cloudtrail_rules/aws_root_activity.yml)
  - Root account activity was detected.
- [Root Console Login](../rules/aws_cloudtrail_rules/aws_console_root_login.yml)
  - The root account has been logged into.
- [Root Password Changed](../rules/aws_cloudtrail_rules/aws_root_password_changed.yml)
  - Someone manually changed the Root console login password.
- [S3 Bucket Deleted](../rules/aws_cloudtrail_rules/aws_s3_bucket_deleted.yml)
  - A S3 Bucket, Policy, or Website was deleted
- [Secret Exposed and not Quarantined](../correlation_rules/secret_exposed_and_not_quarantined.yml)
  - The rule detects when a GitHub Secret Scan detects an exposed secret, which is not followed by the expected quarantine operation in AWS.  When you make a repository public, or push changes to a public repository, GitHub always scans the code for secrets that match partner patterns. Public packages on the npm registry are also scanned. If secret scanning detects a potential secret, we notify the service provider who issued the secret. The service provider validates the string and then decides whether they should revoke the secret, issue a new secret, or contact you directly. Their action will depend on the associated risks to you or them.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [StopInstance FOLLOWED BY ModifyInstanceAttributes](../correlation_rules/aws_cloudtrail_stopinstance_followed_by_modifyinstanceattributes.yml)
  - Identifies when StopInstance and ModifyInstanceAttributes CloudTrail events occur in a short period of time. Since EC2 startup scripts cannot be modified without first stopping the instance, StopInstances should be a signal.
- [Unused AWS Region](../rules/aws_cloudtrail_rules/aws_unused_region.yml)
  - CloudTrail logged non-read activity from a verboten AWS region.


## AWS CloudWatch

- [AWS CloudWatch Log Encryption](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_encrypted.yml)
  - AWS automatically performs server-side encryption of logs, but you can encrypt with your own CMK to protect extra sensitive log data.
- [AWS CloudWatch Logs Data Retention](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_data_retention.yml)
  - By default, logs are kept indefinitely and never expire. You can adjust the retention policy for each log group, keeping the indefinite retention, or choosing a specific retention period.
- [Sensitive AWS CloudWatch Log Encryption](../policies/aws_cloudwatch_policies/aws_cloudwatch_loggroup_sensitive_encrypted.yml)
  - AWS automatically performs server-side encryption of logs, but you can encrypt with your own CMK to protect extra sensitive log data.


## AWS Config

- [AWS Config Global Resources](../policies/aws_config_policies/aws_config_global_resources.yml)
  - You can have AWS Config record supported types of global resources, such as IAM users, groups, roles, and customer managed policies.
- [AWS Config Recording Status](../policies/aws_config_policies/aws_config_recording_no_error.yml)
  - This policy ensures that the config recorder is operational and capturing changes to your account without error.
- [AWS Config Records All Resource Types](../policies/aws_config_policies/aws_config_all_resource_types.yml)
  - This policy ensurers that you have a comprehensive configuration audit in place for all resource types in AWS.
- [AWS Config Status](../policies/aws_config_policies/aws_config_recording_enabled.yml)
  - This policy ensures that the config recorder is operational and capturing changes to your account.


## AWS DynamoDB

- [AWS DynamoDB Table Autoscaling](../policies/aws_dynamodb_policies/aws_dynamodb_autoscaling.yml)
  - DynamoDB Auto Scaling can dynamically adjust provisioned throughput capacity in response to traffic patterns. This enables a table to increase its provisioned read and write capacity to handle sudden increases in traffic
- [AWS DynamoDB Table Autoscaling Configuration](../policies/aws_dynamodb_policies/aws_dynamodb_autoscaling_configuration.yml)
  - DynamoDB Auto Scaling can dynamically adjust provisioned throughput capacity in response to traffic patterns. This enables a table to increase its provisioned read and write capacity to handle sudden increases in traffic
- [AWS DynamoDB Table TTL](../policies/aws_dynamodb_policies/aws_dynamodb_table_ttl_enabled.yml)
  - This policy validates that all DynamoDB tables have a TTL field configured.


## AWS EC2

- [AWS AMI Sharing](../policies/aws_ec2_policies/aws_ami_private.yml)
  - This policy ensures that AMIs you have created are not configured to allow public access, which could result in accidental data loss. AMI's that you use but do not own are not evaluated by this policy.
- [AWS CDE EC2 Volume Encryption](../policies/aws_ec2_policies/aws_ec2_cde_volume_encrypted.yml)
  - This policy ensures that all EC2 volumes that contain CDE are encrypted. Be sure to configure CDE definitions before enabling this policy.
- [AWS EC2 AMI Approved Host](../policies/aws_ec2_policies/aws_ec2_ami_approved_host.yml)
  - Checks that AWS EC2 AMI's are only launched on approved dedicated hosts.
- [AWS EC2 AMI Approved Instance Type](../policies/aws_ec2_policies/aws_ec2_ami_approved_instance_type.yml)
  - This policy ensures that the EC2 instance is running with an instance type approved for its AMI.
- [AWS EC2 AMI Approved Tenancy](../policies/aws_ec2_policies/aws_ec2_ami_approved_tenancy.yml)
  - This policy ensures that the EC2 instance was launched with a tenancy approved for its AMI.
- [AWS EC2 Instance Approved AMI](../policies/aws_ec2_policies/aws_ec2_instance_approved_ami.yml)
  - This policy ensures the given EC2 instance is running an AMI from the approved list of AMI's.
- [AWS EC2 Instance Approved Host](../policies/aws_ec2_policies/aws_ec2_instance_approved_host.yml)
  - This policy ensures the given EC2 Instance is running on an approved dedicated host.
- [AWS EC2 Instance Approved Instance Type](../policies/aws_ec2_policies/aws_ec2_instance_approved_instance_type.yml)
  - This policy ensures that the EC2 instance is running on one of the approved instance types.
- [AWS EC2 Instance Approved Tenancy](../policies/aws_ec2_policies/aws_ec2_instance_approved_tenancy.yml)
  - This policy ensures the given EC2 Instance is running with an approved tenancy option. The possible tenancy options are dedicated, host, and default.
- [AWS EC2 Instance Approved VPC](../policies/aws_ec2_policies/aws_ec2_instance_approved_vpc.yml)
  - This policy ensures that the given EC2 Instance is running in an approved VPC.
- [AWS EC2 Instance Detailed Monitoring](../policies/aws_ec2_policies/aws_ec2_instance_detailed_monitoring.yml)
  - This policy ensures that the AWS Instance has Detailed Monitoring Enabled
- [AWS EC2 Instance EBS Optimization](../policies/aws_ec2_policies/aws_ec2_instance_ebs_optimization.yml)
  - This policy ensures EBS optimization is enabled for the given EC2 instance, if applicable.
- [AWS EC2 Volume Encryption](../policies/aws_ec2_policies/aws_ec2_volume_encryption.yml)
  - You can encrypt both the boot and data volumes of an EC2 instance.
- [AWS EC2 Volume Snapshot Encryption](../policies/aws_ec2_policies/aws_ec2_volume_snapshot_encrypted.yml)
  - You can encrypt the snapshot of an EC2 volume to protect against accidental data loss
- [AWS Network ACL Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_network_acl_restricts_inbound_traffic.yml)
  - This policy validates that Network ACLs restrict inbound traffic in some way.
- [AWS Network ACL Restricts Insecure Protocols](../policies/aws_vpc_policies/aws_network_acl_restricts_insecure_protocols.yml)
  - This policy validates that Network ACLs block the usage of ports typically associated with insecure or unencrypted protocols.
- [AWS Network ACL Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_network_acl_restricts_outbound_traffic.yml)
  - This policy validates that Network ACLs have some restrictions on outbound traffic.
- [AWS Network ACL Restricts SSH](../policies/aws_vpc_policies/aws_network_acl_restricted_ssh.yml)
  - SSH access should only be granted from protected network CIDR ranges.
- [AWS Resource Minimum Tags ](../policies/aws_account_policies/aws_resource_minimum_tags.yml)
  - This policy ensures that applicable resources have a minimum number of tags set.
- [AWS Resource Required Tags](../policies/aws_account_policies/aws_resource_required_tags.yml)
  - This policy ensures that AWS resources have specific tags, dependent on their resource type.
- [AWS Security Group - Only DMZ Publicly Accessible](../policies/aws_vpc_policies/aws_only_dmz_security_groups_publicly_accessible.yml)
  - This policy validates that only Security Groups designated as DMZs allow inbound traffic from public IP space. This helps ensure no traffic is bypassing the DMZ.
- [AWS Security Group Administrative Ingress](../policies/aws_vpc_policies/aws_security_group_administrative_ingress.yml)
  - This policy validates that AWS Security Groups don't allow unrestricted inbound traffic on port 3389 or 22, ports commonly used for the remote access protocols RDP and SSH respectively.
- [AWS Security Group Restricts Access To CDE](../policies/aws_vpc_policies/aws_security_group_restricts_access_to_cde.yml)
  - This policy validates that are considered part of the PCI CDE do not allow any access from public IP space.
- [AWS Security Group Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_inbound_traffic.yml)
  - This policy validates that Security Groups have some restrictions on inbound traffic.
- [AWS Security Group Restricts Inter-SG Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_inter_security_group_traffic.yml)
  - This policy validates that Security Groups have restrictions on inter Security Group traffic. Administrators may assume there is an implicit level of trust between Security Groups in the same account, but this is not always a good assumption in cases one Security Group contains far more sensitive data that another.
- [AWS Security Group Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_security_group_restricts_outbound_traffic.yml)
  - This policy validates that Security Groups have some restrictions on outbound traffic.
- [AWS Security Group Restricts Traffic Leaving CDE](../policies/aws_vpc_policies/aws_security_group_restricts_traffic_leaving_cde.yml)
  - This policy validates that there are restrictions on what type of traffic may leave Security Groups that are considered with the scope of the PCI CDE. These restrictions help ensure that cardholder data does not leave the CDE.
- [AWS Security Group Tightly Restricts Inbound Traffic](../policies/aws_vpc_policies/aws_security_group_tightly_restricts_inbound_traffic.yml)
  - This policy validates that Security Groups have restrictive permission sets that both limit the total number of open ports, as well as limiting ports typically associated with insecure protocols.
- [AWS Security Group Tightly Restricts Outbound Traffic](../policies/aws_vpc_policies/aws_security_group_tightly_restricts_outbound_traffic.yml)
  - This policy validates that Security Groups have restrictive controls on outbound traffic.
- [AWS VPC Default Network ACL Restricts All Traffic](../policies/aws_vpc_policies/aws_vpc_default_network_acl_restricts_all_traffic.yml)
  - This policy validates that the default Network ACL for a given AWS VPC is restricting all inbound and outbound traffic.
- [AWS VPC Default Security Group Restrictions ](../policies/aws_vpc_policies/aws_vpc_default_security_restrictions.yml)
  - This policy validates that the default Security Group for a given AWS VPC is restricting all inbound and outbound traffic.
- [AWS VPC Flow Logs](../policies/aws_vpc_policies/aws_vpc_flow_logs.yml)
  - This policy validates that AWS VPCs (Virtual Private Clouds) have network flow logging enabled.


## AWS EKS

- [EKS Anonymous API Access Detected](../rules/aws_eks_rules/anonymous_api_access.yml)
  - This rule detects anonymous API requests made to the Kubernetes API server. In production environments, anonymous access should be disabled to prevent unauthorized access to the API server.
- [EKS Audit Log based single sourceIP is generating multiple 403s](../rules/aws_eks_rules/source_ip_multiple_403.yml)
  - This detection identifies if a public sourceIP is generating multiple 403s with the Kubernetes API server.
- [EKS Audit Log Reporting system Namespace is Used From A Public IP](../rules/aws_eks_rules/system_namespace_public_ip.yml)
  - This detection identifies if an activity is recorded in the Kubernetes audit log where the user:username attribute begins with "system:" or "eks:" and the requests originating IP Address is a Public IP Address
- [IOC Activity in K8 Control Plane](../queries/kubernetes_queries/kubernetes_ioc_activity_query.yml)
  - This detection monitors for any kubernetes API Request originating from an Indicator of Compromise.
- [Kubernetes Cron Job Created or Modified](../queries/kubernetes_queries/kubernetes_cron_job_created_or_modified_query.yml)
  - This detection monitor for any modifications or creations of a cron job. Attackers may create or modify an existing scheduled job in order to achieve cluster persistence.
- [Kubernetes Pod Created in Pre-Configured or Default Name Spaces](../queries/kubernetes_queries/kubernetes_pod_in_default_name_space_query.yml)
  - This detection monitors for any pod created in pre-configured or default namespaces. Only Cluster Admins should be creating pods in the kube-system namespace, and it is best practice not to run any cluster critical infrastructure here. The kube-public namespace is intended to be readable by unauthenticated users. The default namespace is shipped with the cluster and it is best practice not to deploy production workloads here. These namespaces may be used to evade defenses or hide attacker infrastructure.
- [New Admission Controller Created](../queries/kubernetes_queries/kubernetes_admission_controller_created_query.yml)
  - This detection monitors for a new admission controller being created in the cluster. Admission controllers allows an attack to intercept all API requests made within a cluster, allowing for enumeration of resources and common actions. This can be a very powerful tool to understand where to pivot to next.
- [New DaemonSet Deployed to Kubernetes](../queries/kubernetes_queries/kubernetes_new_daemonset_deployed_query.yml)
  - This detection monitors for a new DaemonSet deployed to a kubernetes cluster. A daemonset is a workload that guarantees the presence of exactly one instance of a specific pod on every node in the cluster. This can be a very powerful tool for establishing peristence.
- [Pod attached to the Node Host Network](../queries/kubernetes_queries/kubernetes_pod_attached_to_node_host_network_query.yml)
  - This detection monitor for the creation of pods which are attached to the host's network. This allows a pod to listen to all network traffic for all deployed computer on that particular node and communicate with other compute on the network namespace. Attackers can use this to capture secrets passed in arguments or connections.
- [Pod Created or Modified Using the Host IPC Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_ipc_namespace_query.yml)
  - This detection monitors for any pod creation or modification using the host IPC Namespace. Deploying pods in the Host IPC Namespace, breaks isolation between the pod and the underlying host meaning the pod has direct access to the same IPC objects and communications channels as the host system.
- [Pod Created or Modified Using the Host PID Namespace](../queries/kubernetes_queries/kubernetes_pod_using_host_pid_namespace_query.yml)
  - This detection monitors for any pod creation or modification using the host PID namespace. The Host PID namespace enables a pod and its containers to have direct access and share the same view as of the host’s processes. This can offer a powerful escape hatch to the underlying host.
- [Pod Created with Overly Permissive Linux Capabilities](../queries/kubernetes_queries/kubernetes_overly_permissive_linux_capabilities_query.yml)
  - This detection monitors for a pod created with overly permissive linux capabilities. Excessive pod permissions and capabilities can be a launch point for privilege escalation or container breakout.
- [Pod creation or modification to a Host Path Volume Mount](../queries/kubernetes_queries/kubernetes_pod_create_or_modify_host_path_vol_mount_query.yml)
  - This detection monitors for pod creation with a hostPath volume mount. The attachment to a node's volume can allow for privilege escalation through underlying vulnerabilities or it can open up possibilities for data exfiltration or unauthorized file access. It is very rare to see this being a pod requirement.
- [Privileged Pod Created](../queries/kubernetes_queries/kubernetes_privileged_pod_created_query.yml)
  - This detection monitors for a privileged pod is created either by default or with permissions to run as root. These particular pods have full access to the hosts namespace and devices, ability to exploit the kernel, have dangerous linux capabilities, and can be a powerful launching point for further attacks.
- [Secret Enumeration by a User](../queries/kubernetes_queries/kubernetes_secret_enumeration_query.yml)
  - This detection monitors for a large number of secrets requests by a single user. This could potentially indicate secret enumeration, which can potentially enable lateral or vertical movement and unauthorized access to critical resources.
- [Unauthenticated Kubernetes API Request](../queries/kubernetes_queries/kubernetes_unauthenticated_api_request_query.yml)
  - This detection monitors for any unauthenticated kubernetes api request. Unauthenticated Requests are performed by the anonymous user and have unfederated access to the cluster.
- [Unauthorized Kubernetes Pod Execution](../queries/kubernetes_queries/kubernetes_unauthorized_pod_execution_query.yml)
  - This detection monitors for any pod execution in a kubernetes cluster. Pod execution should never be done in a production cluster, and can indicate a user performing unauthorized actions.


## AWS ELBV2

- [AWS Application Load Balancer Web ACL](../policies/aws_elb_policies/aws_application_load_balancer_web_acl.yml)
  - This policy validates that all application load balancers have an associated Web ACl to enforce protections against various web attacks.
- [AWS ELB SSL Policies](../policies/aws_load_balancer_policies/aws_alb_ssl_policy.yml)
  - Ensures that deprecated TLS versions are not supported in internet-facing load balancers
- [AWS Enforces SSL Policies](../policies/aws_load_balancer_policies/aws_elbv2_load_balancer_has_ssl_policy.yml)
  - This policy validates that ELBV2 load balancer listeners are using an SSL policy.


## AWS GuardDuty

- [AWS GuardDuty Critical Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_critical_sev_findings.yml)
  - A critical-severity GuardDuty finding has been identified.
- [AWS GuardDuty Enabled](../policies/aws_guardduty_policies/aws_guardduty_enabled.yml)
  - GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior.
- [AWS GuardDuty High Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_high_sev_findings.yml)
  - A high-severity GuardDuty finding has been identified.
- [AWS GuardDuty Low Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_low_sev_findings.yml)
  - A low-severity GuardDuty finding has been identified.
- [AWS GuardDuty Master Account](../policies/aws_guardduty_policies/aws_guardduty_master_account.yml)
  - Ensure that all GuardDuty logs are sending into a single Master account. This is a best practice for centralizing detection logic and useful data during an investigation.
- [AWS GuardDuty Medium Severity Finding](../rules/aws_guardduty_rules/aws_guardduty_med_sev_findings.yml)
  - A medium-severity GuardDuty finding has been identified.


## AWS IAM

- [AWS Access Key Rotation](../policies/aws_iam_policies/aws_access_key_rotation.yml)
  - This policy validates that AWS IAM account access keys are rotated every 90 days. Rotating access keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used.
- [AWS Access Keys At Account Creation](../policies/aws_iam_policies/aws_access_keys_at_account_creation.yml)
  - This policy validates that AWS IAM user accounts do not have access keys that were created during account creation. This results in excess keys being generated, and unnecessary management work in auditing and rotating these keys.
- [AWS CloudTrail Least Privilege Access](../policies/aws_iam_policies/aws_cloudtrail_least_privilege.yml)
  - Users with permissions to disable or reconfigure CloudTrail should be limited.
- [AWS IAM Group Users](../policies/aws_iam_policies/aws_iam_group_users.yml)
  - This Policy ensures that all IAM groups have at least one IAM user. If they are vacant, they should be deleted.
- [AWS IAM Password Unused](../policies/aws_iam_policies/aws_password_unused.yml)
  - This policy validates IAM users with console passwords have logged in within the past 90 days.
- [AWS IAM Policy Administrative Privileges](../policies/aws_iam_policies/aws_iam_policy_administrative_privileges.yml)
  - This policy validates that there are no IAM policies that grant full administrative privileges to IAM users or groups.
- [AWS IAM Policy Assigned to User](../policies/aws_iam_policies/aws_iam_policy_assigned_to_user.yml)
  - This policy validates that there are no IAM policies assigned directly to users. Best practice suggests assigning to an IAM group and placing users within that group.
- [AWS IAM Policy Blocklist](../policies/aws_iam_policies/aws_iam_policy_blocklist.yml)
  - This detects the usage of highly permissive IAM Policies that should only be assigned to a small number of users, roles, or groups.
- [AWS IAM Policy Does Not Grant Any Administrative Access](../policies/aws_iam_policies/aws_iam_policy_does_not_grant_admin_access.yml)
  - This policy validates that no IAM policies grant admin access. This should be combined with suppressions on the legitimate IAM admin policies in your account so that it only fires when new and unexpected policies granting admin access are created.
- [AWS IAM Policy Does Not Grant Network Admin Access](../policies/aws_iam_policies/aws_iam_policy_does_not_grant_network_admin_access.yml)
  - This policy validates that no IAM policies grant admin privileges on network resources. This should be used in conjunction with suppressions for the legitimate network admin policies in your account.
- [AWS IAM Policy Role Mapping](../policies/aws_iam_policies/aws_iam_policy_role_mapping.yml)
  - This policy validates that policies that have been explicitly configured to be set to certain roles are still attached to those roles.
- [AWS IAM Resource Does Not Have Inline Policy](../policies/aws_iam_policies/aws_iam_resource_does_not_have_inline_policy.yml)
  - This policy validates that no IAM entities have inline policies assigned. Inline policies are more difficult to administer and audit, and may lead to access that lasts longer than intended.
- [AWS IAM Role Grants (permission) to Non-organizational Account](../policies/aws_iam_policies/aws_iam_role_external_permission.yml)
  - This policy validates that IAM roles that grant the (specified) permission do not allow accounts outside the organization to assume them.
- [AWS IAM Role Restricts Usage](../policies/aws_iam_policies/aws_iam_role_restricts_usage.yml)
  - This policy validates that IAM roles in the account are restrictive in what entities may assume them. This can help prevent malicious actors from assuming roles they should not be assuming.
- [AWS IAM Role Trust Relationship for GitHub Actions](../policies/aws_iam_policies/aws_iam_role_github_actions_trust.yml)
  - This policy ensures that IAM roles used with GitHub Actions are securely configured to prevent unauthorized access to AWS resources.  It validates trust relationships by checking for proper audience (aud) restrictions, ensuring it is set to sts.amazonaws.com, and subject (sub) conditions,  confirming they are scoped to specific repositories or environments. Misconfigurations, such as overly permissive wildcards or missing conditions,  can allow unauthorized repositories to assume roles, leading to potential data breaches or compliance violations.  By enforcing these checks, the policy mitigates risks of exploitation, enhances security posture, and protects critical AWS resources from external threats.
- [AWS IAM User MFA ](../policies/aws_iam_policies/aws_iam_user_mfa.yml)
  - This policy validates that all AWS IAM users with access to the AWS Console have Multi-Factor Authentication (MFA) enabled.
- [AWS IAM User Not In Conflicting Groups](../policies/aws_iam_policies/aws_iam_user_not_in_conflicting_groups.yml)
  - This policy validates that IAM users are not in IAM groups that are considered mutually exclusive. For example, in some workflows developers are responsible for dev environments and sysadmins are responsible for prod environments. In this situation no (or very few) users should be in both sysadmin and developer groups. This is in following with the principle of least privilege.
- [AWS Resource Minimum Tags ](../policies/aws_account_policies/aws_resource_minimum_tags.yml)
  - This policy ensures that applicable resources have a minimum number of tags set.
- [AWS Resource Required Tags](../policies/aws_account_policies/aws_resource_required_tags.yml)
  - This policy ensures that AWS resources have specific tags, dependent on their resource type.
- [AWS Root Account Access Keys](../policies/aws_iam_policies/aws_root_account_access_keys.yml)
  - This policy validates that no programmatic access keys exist for the root account.
- [AWS Root Account Hardware MFA](../policies/aws_iam_policies/aws_root_account_hardware_mfa.yml)
  - This policy validates that a hardware MFA device is in use for access to the root account.
- [AWS Root Account MFA](../policies/aws_iam_policies/aws_root_account_mfa.yml)
  - This policy validates that Multi Factor Authentication (MFA) is required for access to the root account.
- [AWS Unused Access Key](../policies/aws_iam_policies/aws_access_key_unused.yml)
  - This policy validates that IAM user access keys are used at least once every 90 days.
- [IAM Inline Policy Network Admin](../policies/aws_iam_policies/aws_iam_inline_policy_does_not_grant_network_admin_access.yml)
  - This policy validates that IAM entities (Groups, Roles, and Users) do not have inline policies attached that grant network admin privileges. Inline policies are more difficult to track and audit than managed policies, and can lead to persistent unexpected access.


## AWS KMS

- [AWS KMS CMK Key Rotation](../policies/aws_kms_policies/aws_cmk_key_rotation.yml)
  - This policy validates that customer master keys (CMKs) have automatic key rotation enabled.
- [AWS KMS Key Restricts Usage](../policies/aws_kms_policies/aws_kms_key_policy_restricts_usage.yml)
  - This policy validates that KMS Keys restrict what entities can use them and how. This is to ensure that encryption keys are limited in who can use them in order to prevent unapproved decryption.


## AWS Lambda

- [AWS Lambda Public Access](../policies/aws_lambda_policies/aws_lambda_public_access.yml)
  - This policy ensures that the function policy attached to the Lambda resource prohibits public access


## AWS PasswordPolicy

- [AWS Password Policy Complexity Guidelines](../policies/aws_account_policies/aws_password_policy_complexity_guidelines.yml)
  - This policy validates that the account password policy enforces the recommended password complexity requirements.
- [AWS Password Policy Password Age Limit](../policies/aws_account_policies/aws_password_policy_password_age_limit.yml)
  - This policy validates that the account password policy enforces a maximum password age of 90 days or less.
- [AWS Password Policy Password Reuse](../policies/aws_account_policies/aws_password_policy_password_reuse.yml)
  - This policy validates that the account password policy prevents users from re-using previous passwords, and prevents password reuse for 24 or more prior passwords.


## AWS RDS

- [AWS RDS Instance Backup](../policies/aws_rds_policies/aws_rds_instance_backup.yml)
  - This Policy ensures that RDS Instances have Backups enabled. Backups are an important aspect of disaster recovery that can protect sensitive data from destruction.
- [AWS RDS Instance Encryption](../policies/aws_rds_policies/aws_rds_instance_encryption.yml)
  - This policy validates that RDS instances have encryption enabled.
- [AWS RDS Instance Has Acceptable Backup Retention Period](../policies/aws_rds_policies/aws_rds_instance_backup_retention_acceptable.yml)
  - This policy validates that RDS instances are configured with a backup retention period that is acceptable to company policy. This ensures for both compliance and security reasons that records are kept for a minimum period of time, and for compliance and performance reasons that records are not kept indefinitely.
- [AWS RDS Instance High Availability](../policies/aws_rds_policies/aws_rds_instance_high_availability.yml)
  - This Policy ensures that RDS Instances have are running in High Availability mode to provide redundancy in the event of an operational failure. For Aurora, storage is replicated across all the Availability Zones and doesn't require this setting.
- [AWS RDS Instance Minor Version Upgrades](../policies/aws_rds_policies/aws_rds_instance_auto_minor_version_upgrade_enabled.yml)
  - If you want Amazon RDS to upgrade the DB engine version of a database automatically, you can enable auto minor version upgrades for the database.
- [AWS RDS Instance Public Access](../policies/aws_rds_policies/aws_rds_instance_public_access.yml)
  - This Policy checks that an RDS Instance is not accessible from the public internet.
- [AWS RDS Instance Snapshot Public Access](../policies/aws_rds_policies/aws_rds_instance_snapshot_public_access.yml)
  - This policy validates that RDS Instance snapshots are not publicly restorable. This would allow anyone to restore an old version of your database and have full access to its contents.


## AWS Redshift

- [AWS Redshift Cluster Encryption](../policies/aws_redshift_policies/aws_redshift_cluster_encryption.yml)
  - This policy validates that Redshift Clusters have encryption enabled.
- [AWS Redshift Cluster Has Acceptable Snapshot Retention Period](../policies/aws_redshift_policies/aws_redshift_cluster_snapshot_retention_acceptable.yml)
  - This policy validates that Redshift Cluster snapshot retention periods are set to an appropriate time. This ensures that records are kept long enough for compliance and security reasons, but no too long for compliance and performance reasons.
- [AWS Redshift Cluster Logging](../policies/aws_redshift_policies/aws_redshift_cluster_logging.yml)
  - This policy validates that Redshift Cluster have logging enabled. This includes audit logs.
- [AWS Redshift Cluster Maintenance Window](../policies/aws_redshift_policies/aws_redshift_cluster_maintenance_window.yml)
  - This policy validates that Redshift Clusters have the correct preferred maintenance window configured.
- [AWS Redshift Cluster Snapshot Retention](../policies/aws_redshift_policies/aws_redshift_cluster_snapshot_retention.yml)
  - This policy validates that Redshift Clusters have sufficient snapshot retention periods, so that snapshots are not lost before they are needed.
- [AWS Redshift Cluster Version Upgrade](../policies/aws_redshift_policies/aws_redshift_cluster_version_upgrade.yml)
  - This policy validates that Redshift Clusters automatically perform upgrades during scheduled maintenance windows.


## AWS S3

- [AWS S3 Bucket Action Restrictions](../policies/aws_s3_policies/aws_s3_bucket_action_restrictions.yml)
  - Ensures that the S3 bucket policy does not allow any action on the bucket, in accordance with the principal of least privilege.
- [AWS S3 Bucket Encryption](../policies/aws_s3_policies/aws_s3_bucket_encryption.yml)
  - Ensures that the S3 bucket has encryption enabled.
- [AWS S3 Bucket Lifecycle Configuration](../policies/aws_s3_policies/aws_s3_bucket_lifecycle_configuration.yml)
  - Verifies that the S3 Bucket Object Lifecycle configuration expires data within 90 and 365 days.
- [AWS S3 Bucket Logging](../policies/aws_s3_policies/aws_s3_bucket_logging.yml)
  - Ensures that a logging policy is set for the S3 bucket.
- [AWS S3 Bucket MFA Delete](../policies/aws_s3_policies/aws_s3_bucket_mfa_delete.yml)
  - Ensures that MFA delete is enabled for a bucket so that all objects can only be deleted by users authenticated with MFA.
- [AWS S3 Bucket Name DNS Compliance](../policies/aws_s3_policies/aws_s3_bucket_name_dns_compliance.yml)
  - This policy validates that the AWS S3 bucket name is DNS compliant.
- [AWS S3 Bucket Object Lock Configured](../policies/aws_s3_policies/aws_s3_bucket_object_lock_configured.yml)
  - This policy validates that S3 buckets have an Object Lock configuration enabled. This should be used with specific suppression lists to ensure it is applied only to appropriate S3 buckets, such as those containing CloudTrail or other auditable records.
- [AWS S3 Bucket Policy Allow With Not Principal](../policies/aws_s3_policies/aws_s3_bucket_policy_allow_with_not_principal.yml)
  - Prevents the use of a 'Not' principal in conjunction with an allow effect in an S3 bucket policy, which would allow global access for the resource besides the principals specified.
- [AWS S3 Bucket Principal Restrictions](../policies/aws_s3_policies/aws_s3_bucket_principal_restrictions.yml)
  - This policy validates that S3 Bucket access policies do not allow all users (Principal:"*") for a given action on the bucket, in accordance with the principle of least privilege.
- [AWS S3 Bucket Public Access Block](../policies/aws_s3_policies/aws_s3_bucket_public_access_block.yml)
  - Ensures that a Public Access Block Configuration is set for the given S3 bucket.
- [AWS S3 Bucket Public Read](../policies/aws_s3_policies/aws_s3_bucket_public_read.yml)
  - Ensures that the S3 bucket is not publicly readable.
- [AWS S3 Bucket Public Write](../policies/aws_s3_policies/aws_s3_bucket_public_write.yml)
  - Ensures that the S3 bucket is not publicly writeable.
- [AWS S3 Bucket Secure Access](../policies/aws_s3_policies/aws_s3_bucket_secure_access.yml)
  - Ensures access to S3 buckets is forced to use a secure (HTTPS) connection.
- [AWS S3 Bucket Versioning](../policies/aws_s3_policies/aws_s3_bucket_versioning.yml)
  - Checks that object versioning is enabled in the S3 bucket.
- [S3 Bucket Policy Confused Deputy Protection for Service Principals](../policies/aws_s3_policies/aws_s3_bucket_policy_confused_deputy.yml)
  - Ensures that S3 bucket policies with service principals include conditions to prevent the confused deputy problem.


## AWS S3ServerAccess

- [AWS S3 Access Error](../rules/aws_s3_rules/aws_s3_access_error.yml)
  - Checks for errors during S3 Object access. This could be due to insufficient access permissions, non-existent buckets, or other reasons.
- [AWS S3 Access IP Allowlist](../rules/aws_s3_rules/aws_s3_access_ip_allowlist.yml)
  - Checks that the remote IP accessing the S3 bucket is in the IP allowlist.
- [AWS S3 Insecure Access](../rules/aws_s3_rules/aws_s3_insecure_access.yml)
  - Checks if HTTP (unencrypted) was used to access objects in an S3 bucket, as opposed to HTTPS (encrypted).
- [AWS S3 Unauthenticated Access](../rules/aws_s3_rules/aws_s3_unauthenticated_access.yml)
  - Checks for S3 access attempts where the requester is not an authenticated AWS user.
- [AWS S3 Unknown Requester](../rules/aws_s3_rules/aws_s3_unknown_requester_get_object.yml)
  - Validates that proper IAM entities are accessing sensitive data buckets.


## AWS SecurityFindingFormat

- [Decoy DynamoDB Accessed](../rules/aws_securityfinding_rules/decoy_dynamodb_accessed.yml)
  - Actor accessed Decoy DynamoDB
- [Decoy IAM Assumed](../rules/aws_securityfinding_rules/decoy_iam_assumed.yml)
  - Actor assumed decoy IAM role
- [Decoy S3 Accessed](../rules/aws_securityfinding_rules/decoy_s3_accessed.yml)
  - Actor accessed S3 Manager decoy secret
- [Decoy Secret Accessed](../rules/aws_securityfinding_rules/decoy_secret_accessed.yml)
  - Actor accessed Secrets Manager decoy secret
- [Decoy Systems Manager Parameter Accessed](../rules/aws_securityfinding_rules/decoy_systems_manager_parameter_accessed.yml)
  - Actor accessed Decoy Systems Manager parameter


## AWS VPCDns

- [AWS DNS Crypto Domain](../rules/aws_vpc_flow_rules/aws_dns_crypto_domain.yml)
  - Identifies clients that may be performing DNS lookups associated with common currency mining pools.
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
  - Detects DNS queries with Base64 encoded subdomains, which could indicate an attempt to obfuscate data exfil.
- [VPC DNS Tunneling](../queries/aws_queries/vpc_dns_tunneling.yml)
  - Detect dns tunneling traffic using a scheduled query


## AWS VPCFlow

- [AWS VPC Healthy Log Status](../rules/aws_vpc_flow_rules/aws_vpc_healthy_log_status.yml)
  - Checks for the log status `SKIPDATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.
- [VPC Flow Logs Inbound Port Allowlist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_allowlist.yml)
  - VPC Flow Logs observed inbound traffic violating the port allowlist.
- [VPC Flow Logs Inbound Port Blocklist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_blocklist.yml)
  - VPC Flow Logs observed inbound traffic violating the port blocklist.
- [VPC Flow Logs Unapproved Outbound DNS Traffic](../rules/aws_vpc_flow_rules/aws_vpc_unapproved_outbound_dns.yml)
  - Alerts if outbound DNS traffic is detected to a non-approved DNS server. DNS is often used as a means to exfiltrate data or perform command and control for compromised hosts. All DNS traffic should be routed through internal DNS servers or trusted 3rd parties.
- [VPC Flow Port Scanning](../queries/aws_queries/anomalous_vpc_port_activity_query.yml)
  - Instances of a srcAddr communicating with multiple ports on a dstAddr could indicate port scanning activity.
- [Wiz Issue Followed By SSH to EC2 Instance](../correlation_rules/wiz_issue_followed_by_ssh.yml)
  - Wiz detected a security issue with an EC2 instance followed by an SSH connection to the instance. This sequence could indicate a potential security breach.


## AWS WAF

- [AWS WAF Has XSS Predicate](../policies/aws_waf_policies/aws_waf_has_xss_predicate.yml)
  - This policy validates that all WAF's have at least one rule with a predicate matching on and blocking XSS attacks.
- [AWS WAF Logging Configured](../policies/aws_waf_policies/aws_waf_logging_configured.yml)
  - Ensures that AWS WAF logging is enabled and that the logs are being sent to a valid destination (S3, CloudWatch, or Kinesis Firehose). Without logging, visibility into WAF activity is severely limited, increasing the risk of undetected attacks.
- [AWS WAF Rule Ordering](../policies/aws_waf_policies/aws_waf_rule_ordering.yml)
  - This policy validates that all WAF's have the correct rule ordering. Incorrect rule ordering could lead to less restrictive rules being matched and allowing traffic through before more restrictive rules that should have blocked the traffic.
- [AWS WAF WebACL Has Associated Resources](../policies/aws_waf_policies/aws_waf_webacl_has_associated_resources.yml)
  - This policy ensures that AWS WAF WebACLs are associated with at least one resource (ALB, CloudFront Distribution, or API Gateway). If a WebACL is not associated with any resources, it is inactive and not providing any protection.


