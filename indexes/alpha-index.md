# Alpha Index

- [A](#A)
- [B](#B)
- [C](#C)
- [D](#D)
- [G](#G)
- [M](#M)
- [N](#N)
- [O](#O)
- [P](#P)
- [S](#S)
- [T](#T)
- [W](#W)
- [Z](#Z)
# A

- [AWS ACM](#aws-acm)
- [AWS CloudFormation](#aws-cloudformation)
- [AWS CloudTrail](#aws-cloudtrail)
- [AWS CloudWatch](#aws-cloudwatch)
- [AWS Config](#aws-config)
- [AWS DynamoDB](#aws-dynamodb)
- [AWS EC2](#aws-ec2)
- [AWS EKS](#aws-eks)
- [AWS ELBV2](#aws-elbv2)
- [AWS GuardDuty](#aws-guardduty)
- [AWS IAM](#aws-iam)
- [AWS KMS](#aws-kms)
- [AWS Lambda](#aws-lambda)
- [AWS PasswordPolicy](#aws-passwordpolicy)
- [AWS RDS](#aws-rds)
- [AWS Redshift](#aws-redshift)
- [AWS S3](#aws-s3)
- [AWS S3ServerAccess](#aws-s3serveraccess)
- [AWS SecurityFindingFormat](#aws-securityfindingformat)
- [AWS VPCDns](#aws-vpcdns)
- [AWS VPCFlow](#aws-vpcflow)
- [AWS WAF](#aws-waf)
- [AppOmni](#appomni)
- [Asana](#asana)
- [Atlassian](#atlassian)
- [Auth0](#auth0)
- [Azure](#azure)


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


## AppOmni

- [AppOmni Alert Passthrough](../rules/appomni_rules/appomni_alert_passthrough.yml)


## Asana

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Asana Service Account Created](../rules/asana_rules/asana_service_account_created.yml)
  - An Asana service account was created by someone in your organization.
- [Asana Team Privacy Public](../rules/asana_rules/asana_team_privacy_public.yml)
  - An Asana team's privacy setting was changed to public to the organization (not public to internet)
- [Asana Workspace Default Session Duration Never](../rules/asana_rules/asana_workspace_default_session_duration_never.yml)
  - An Asana workspace's default session duration (how often users need to re-authenticate) has been changed to never.
- [Asana Workspace Email Domain Added](../rules/asana_rules/asana_workspace_email_domain_added.yml)
  - A new email domain has been added to an Asana workspace. Reviewer should validate that the new domain is a part of the organization.
- [Asana Workspace Form Link Auth Requirement Disabled](../rules/asana_rules/asana_workspace_form_link_auth_requirement_disabled.yml)
  - An Asana Workspace Form Link is a unique URL that allows you to create a task directly within a specific Workspace or Project in Asana, using a web form. Disabling authentication requirements may allow unauthorized users to create tasks.
- [Asana Workspace Guest Invite Permissions Anyone](../rules/asana_rules/asana_workspace_guest_invite_permissions_anyone.yml)
  - Typically inviting guests to Asana is permitted by few users. Enabling anyone to invite guests can potentially lead to unauthorized users gaining access to Asana.
- [Asana Workspace New Admin](../rules/asana_rules/asana_workspace_new_admin.yml)
  - Admin role was granted to the user who previously did not have admin permissions
- [Asana Workspace Org Export](../rules/asana_rules/asana_workspace_org_export.yml)
  - An Asana user started an org export.
- [Asana Workspace Password Requirements Simple](../rules/asana_rules/asana_workspace_password_requirements_simple.yml)
  - An asana user made your organization's password requirements less strict.
- [Asana Workspace Require App Approvals Disabled](../rules/asana_rules/asana_workspace_require_app_approvals_disabled.yml)
  - An Asana user turned off app approval requirements for an application type for your organization.
- [Asana Workspace SAML Optional](../rules/asana_rules/asana_workspace_saml_optional.yml)
  - An Asana user made SAML optional for your organization.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
  - A user has subsequent logins from two geographic locations that are very far apart
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## Atlassian

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Atlassian admin impersonated another user](../rules/atlassian_rules/user_logged_in_as_user.yml)
  - Reports when an Atlassian user logs in (impersonates) another user.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## Auth0

- [Auth0 CIC Credential Stuffing](../rules/auth0_rules/auth0_cic_credential_stuffing.yml)
  - Okta has determined that the cross-origin authentication feature in Customer Identity Cloud (CIC) is prone to being targeted by threat actors orchestrating credential-stuffing attacks.  Okta has observed suspicious activity that started on April 15, 2024.  Review tenant logs for unexpected fcoa, scoa, and pwd_leak events.
- [Auth0 CIC Credential Stuffing Query](../queries/auth0_queries/auth0_cic_credential_stuffing_query.yml)
  - Okta has determined that the cross-origin authentication feature in Customer Identity Cloud (CIC) is prone to being targeted by threat actors orchestrating credential-stuffing attacks.  Okta has observed suspicious activity that started on April 15, 2024.  Review tenant logs for unexpected fcoa, scoa, and pwd_leak events.  https://sec.okta.com/articles/2024/05/detecting-cross-origin-authentication-credential-stuffing-attacks
- [Auth0 Custom Role Created](../rules/auth0_rules/auth0_custom_role_created.yml)
  - An Auth0 User created a role in your organization's tenant.
- [Auth0 Integration Installed](../rules/auth0_rules/auth0_integration_installed.yml)
  - An Auth0 integration was installed from the auth0 action library.
- [Auth0 mfa factor enabled](../rules/auth0_rules/auth0_mfa_factor_setting_enabled.yml)
  - An Auth0 user enabled an mfa factor in your organization's mfa settings.
- [Auth0 MFA Policy Disabled](../rules/auth0_rules/auth0_mfa_policy_disabled.yml)
  - An Auth0 User disabled MFA for your organization's tenant.
- [Auth0 MFA Policy Enabled](../rules/auth0_rules/auth0_mfa_policy_enabled.yml)
  - An Auth0 User enabled MFA Policy for your organization's tenant.
- [Auth0 MFA Risk Assessment Disabled](../rules/auth0_rules/auth0_mfa_risk_assessment_disabled.yml)
  - An Auth0 User disabled the mfa risk assessment setting for your organization's tenant.
- [Auth0 MFA Risk Assessment Enabled](../rules/auth0_rules/auth0_mfa_risk_assessment_enabled.yml)
  - An Auth0 User enabled the mfa risk assessment setting for your organization's tenant.
- [Auth0 Post Login Action Flow Updated](../rules/auth0_rules/auth0_post_login_action_flow.yml)
  - An Auth0 User updated a post login action flow for your organization's tenant.
- [Auth0 User Invitation Created](../rules/auth0_rules/auth0_user_invitation_created.yml)
- [Auth0 User Joined Tenant](../rules/auth0_rules/auth0_user_joined_tenant.yml)
  - User accepted invitation from Auth0 member to join an Auth0 tenant.


## Azure

- [Azure Invite External Users](../rules/azure_signin_rules/azure_invite_external_users.yml)
  - This detection looks for a Azure users inviting external users
- [Azure Many Failed SignIns](../rules/azure_signin_rules/azure_failed_signins.yml)
  - This detection looks for a number of failed sign-ins for the same ServicePrincipalName or UserPrincipalName
- [Azure MFA Disabled](../rules/azure_signin_rules/azure_mfa_disabled.yml)
  - This detection looks for MFA being disabled in conditional access policy
- [Azure Policy Changed](../rules/azure_signin_rules/azure_policy_changed.yml)
  - This detection looks for policy changes in AuditLogs
- [Azure RiskLevel Passthrough](../rules/azure_signin_rules/azure_risklevel_passthrough.yml)
  - This detection surfaces an alert based on riskLevelAggregated, riskLevelDuringSignIn, and riskState.riskLevelAggregated and riskLevelDuringSignIn are only expected for Azure AD Premium P2 customers.
- [Azure Role Changed PIM](../rules/azure_signin_rules/azure_role_changed_pim.yml)
  - This detection looks for a change in member's PIM roles in EntraID
- [Azure SignIn via Legacy Authentication Protocol](../rules/azure_signin_rules/azure_legacyauth.yml)
  - This detection looks for Successful Logins that have used legacy authentication protocols
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


# B

- [Box](#box)


## Box

- [Box Access Granted](../rules/box_rules/box_access_granted.yml)
  - A user granted access to their box account to Box technical support from account settings.
- [Box Content Workflow Policy Violation](../rules/box_rules/box_policy_violation.yml)
  - A user violated the content workflow policy.
- [Box event triggered by unknown or external user](../rules/box_rules/box_event_triggered_externally.yml)
  - An external user has triggered a box enterprise event.
- [Box item shared externally](../rules/box_rules/box_item_shared_externally.yml)
  - A user has shared an item and it is accessible to anyone with the share link (internal or external to the company). This rule requires that the boxsdk[jwt] be installed in the environment.
- [Box Large Number of Downloads](../rules/box_rules/box_user_downloads.yml)
  - A user has exceeded the threshold for number of downloads within a single time frame.
- [Box Large Number of Permission Changes](../rules/box_rules/box_user_permission_updates.yml)
  - A user has exceeded the threshold for number of folder permission changes within a single time frame.
- [Box New Login](../rules/box_rules/box_new_login.yml)
  - A user logged in from a new device.
- [Box Shield Detected Anomalous Download Activity](../rules/box_rules/box_anomalous_download.yml)
  - A user's download activity has altered significantly.
- [Box Shield Suspicious Alert Triggered](../rules/box_rules/box_suspicious_login_or_session.yml)
  - A user login event or session event was tagged as medium to high severity by Box Shield.
- [Box Untrusted Device Login](../rules/box_rules/box_untrusted_device.yml)
  - A user attempted to login from an untrusted device.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Malicious Content Detected](../rules/box_rules/box_malicious_content.yml)
  - Box has detect malicious content, such as a virus.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


# C

- [CarbonBlack](#carbonblack)
- [CiscoUmbrella](#ciscoumbrella)
- [Cloudflare](#cloudflare)
- [Crowdstrike](#crowdstrike)


## CarbonBlack

- [Carbon Black Admin Role Granted](../rules/carbonblack_rules/cb_audit_admin_grant.yml)
  - Detects when a user is granted Admin or Super Admin permissions.
- [Carbon Black API Key Created or Retrieved](../rules/carbonblack_rules/cb_audit_api_key_created_retrieved.yml)
  - Detects when a user creates a new API key or retrieves an existing key.
- [Carbon Black Data Forwarder Stopped](../rules/carbonblack_rules/cb_audit_data_forwarder_stopped.yml)
  - Detects when a user disables or deletes a Data Forwarder.
- [Carbon Black Log Entry Flagged](../rules/carbonblack_rules/cb_audit_flagged.yml)
  - Detects when Carbon Black has flagged a log as important, such as failed login attempts and locked accounts.
- [Carbon Black Passthrough Rule](../rules/carbonblack_rules/cb_passthrough.yml)
  - This rule enriches and contextualizes security alerts generated by Carbon Black.  The alert title and description are dynamically updated based on data included in the alert log.
- [Carbon Black User Added Outside Org](../rules/carbonblack_rules/cb_audit_user_added_outside_org.yml)
  - Detects when a user from a different organization is added to Carbon Black.


## CiscoUmbrella

- [Cisco Umbrella Domain Blocked](../rules/cisco_umbrella_dns_rules/domain_blocked.yml)
  - Monitor blocked domains
- [Cisco Umbrella Domain Name Fuzzy Matching](../rules/cisco_umbrella_dns_rules/fuzzy_matching_domains.yml)
  - Identify lookups to suspicious domains that could indicate a phishing attack.
- [Cisco Umbrella Suspicious Domains](../rules/cisco_umbrella_dns_rules/suspicious_domains.yml)
  - Monitor suspicious or known malicious domains
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
  - Detects DNS queries with Base64 encoded subdomains, which could indicate an attempt to obfuscate data exfil.
- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)
  - The rule looks for DNS requests to sites potentially posing as SSO domains.


## Cloudflare

- [Cloudflare Bot High Volume](../rules/cloudflare_rules/cloudflare_httpreq_bot_high_volume.yml)
  - Monitors for bots making HTTP Requests at a rate higher than 2req/sec
- [Cloudflare L7 DDoS](../rules/cloudflare_rules/cloudflare_firewall_ddos.yml)
  - Layer 7 Distributed Denial of Service (DDoS) detected


## Crowdstrike

- [1Password Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/onepassword_login_from_crowdstrike_unmanaged_device.yml)
  - Detects 1Password Logins from IP addresses not found in CrowdStrike's AIP list. May indicate unmanaged device being used, or faulty CrowdStrike Sensor.
- [1Password Login From CrowdStrike Unmanaged Device Query](../queries/crowdstrike_queries/onepass_login_from_crowdstrike_unmanaged_device_query.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List.
- [1Password Login From CrowdStrike Unmanaged Device Query (crowdstrike_fdrevent table)](../queries/onepassword_queries/onepass_login_from_crowdstrike_unmanaged_device_FDREvent.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List. (crowdstrike_fdrevent table)
- [AWS Authentication from CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_Query.yml)
  - Detects AWS Authentication events with IP Addresses not found in CrowdStrike's AIP List
- [AWS Authentication from CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/aws_queries/AWS_Authentication_from_CrowdStrike_Unmanaged_Device_FDREvent.yml)
  - Detects AWS Authentication events with IP Addresses not found in CrowdStrike's AIP List
- [Connection to Embargoed Country](../rules/crowdstrike_rules/crowdstrike_connection_to_embargoed_country.yml)
  - Detection to alert when internal asset is communicating with an sanctioned destination. This detection leverages Panther UDM and IPInfo enrichment.
- [Crowdstrike Admin Role Assigned](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_admin_role_assigned.yml)
  - A user was assigned a priviledged role
- [Crowdstrike Allowlist Removed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_allowlist_removed.yml)
  - A user deleted an allowlist
- [Crowdstrike API Key Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_api_key_created.yml)
  - A user created an API Key in CrowdStrike
- [Crowdstrike API Key Deleted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_api_key_deleted.yml)
  - A user deleted an API Key in CrowdStrike
- [Crowdstrike Credential Dumping Tool](../rules/crowdstrike_rules/crowdstrike_credential_dumping_tool.yml)
  - Detects usage of tools commonly used for credential dumping.
- [Crowdstrike Cryptomining Tools ](../rules/crowdstrike_rules/crowdstrike_cryptomining_tools.yml)
  - Detects the execution of known crytocurrency mining tools.
- [Crowdstrike Detection Passthrough](../rules/crowdstrike_rules/crowdstrike_detection_passthrough.yml)
  - Crowdstrike Falcon has detected malicious activity on a host.
- [Crowdstrike Detection Summary](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_detection_summary.yml)
  - Forwards any alerts generated by CrowdStrike to your Panther destinations.
- [Crowdstrike Ephemeral User Account](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_ephemeral_user_account.yml)
  - Detects when a user account is created and deleted within 12 hours. This aims to detect ephemeral user accounts infiltrators might use to avoid suspicion.
- [Crowdstrike FDR LOLBAS](../rules/crowdstrike_rules/crowdstrike_lolbas.yml)
  - Living off the land binaries and script usage
- [Crowdstrike IP Allowlist Changed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_ip_allowlist_changed.yml)
  - Updates were made to Falcon console's allowlist. This could indicate a bad actor permitting access from another machine, or could be attackers preventing legitimate actors from accessing the console.
- [CrowdStrike Large Zip Creation](../queries/crowdstrike_queries/CrowdStrike_Large_Zip_Creation.yml)
  - Detects creation of large zip files, which can indicate attempts of exfiltration
- [CrowdStrike Large Zip Creation (crowdstrike_fdrevent table)](../queries/crowdstrike_queries/CrowdStrike_Large_Zip_Creation_FDREvent.yml)
  - Detects creation of large zip files, which can indicate attempts of exfiltration (crowdstrike_fdrevent table)
- [CrowdStrike MacOS Added Trusted Cert](../rules/crowdstrike_rules/crowdstrike_macos_add_trusted_cert.yml)
  - Detects attempt to install a root certificate on MacOS
- [CrowdStrike MacOS Osascript as Administrator](../rules/crowdstrike_rules/crowdstrike_macos_osascript_administrator.yml)
  - Detects usage of osascript with administrator privileges
- [CrowdStrike MacOS plutil Usage](../rules/crowdstrike_rules/crowdstrike_macos_plutil_usage.yml)
  - Detects the usage of plutil to modify plist files. Plist files run on start up and are often used by attackers to maintain persistence.
- [Crowdstrike New Admin User Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_new_admin_user_created.yml)
  - Detects when a user account is created and assigned admin permissions
- [Crowdstrike New User Created](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_new_user_created.yml)
  - A new Crowdstrike user was created
- [Crowdstrike Real Time Response (RTS) Session](../rules/crowdstrike_rules/crowdstrike_real_time_response_session.yml)
  - Alert when someone uses Crowdstrike’s RTR (real-time response) capability to access a machine remotely to run commands.
- [Crowdstrike Remote Access Tool Execution](../rules/crowdstrike_rules/crowdstrike_remote_access_tool_execution.yml)
  - Detects usage of common remote access tools.
- [Crowdstrike Reverse Shell Tool Executed](../rules/crowdstrike_rules/crowdstrike_reverse_shell_tool_executed.yml)
  - Detects usage of tools commonly used to to establish reverse shells on Windows machines.
- [Crowdstrike Single IP Allowlisted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_single_ip_allowlisted.yml)
  - A single IP (instead of a CIDR range) was allowlisted. This could indicate a bad actor permitting access from another machine.
- [Crowdstrike Systemlog Tampering](../rules/crowdstrike_rules/crowdstrike_systemlog_tampering.yml)
  - Detects when a user attempts to clear system logs.
- [Crowdstrike Unusual Parent Child Processes](../rules/crowdstrike_rules/crowdstrike_unusual_parent_child_processes.yml)
  - Detects unusual parent child process pairings.
- [Crowdstrike User Deleted](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_user_deleted.yml)
  - Someone has deleted multiple users.
- [Crowdstrike User Password Changed](../rules/crowdstrike_rules/event_stream_rules/crowdstrike_password_change.yml)
  - A user's password was changed
- [Crowdstrike WMI Query Detection](../rules/crowdstrike_rules/crowdstrike_wmi_query_detection.yml)
  - Detects execution of WMI queries involving information gathering or actions on remote systems, which could indicate reconnaissance or lateral movement.
- [DNS Base64 Encoded Query](../rules/standard_rules/standard_dns_base64.yml)
  - Detects DNS queries with Base64 encoded subdomains, which could indicate an attempt to obfuscate data exfil.
- [DNS request to denylisted domain](../rules/crowdstrike_rules/crowdstrike_dns_request.yml)
  - A DNS request was made to a domain on an explicit denylist
- [Execution of Command Line Tool with Base64 Encoded Arguments](../rules/crowdstrike_rules/crowdstrike_base64_encoded_args.yml)
  - Detects the execution of common command line tools (e.g., PowerShell, cmd.exe) with Base64 encoded arguments, which could indicate an attempt to obfuscate malicious commands.
- [MacOS Browser Credential Access (crowdstrike_fdrevent table)](../queries/crowdstrike_queries/MacOS_Browser_Credential_Access_FDREvent.yml)
  - Detects processes that contain known browser credential files in arguments. (crowdstrike_fdrevent table)
- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)
  - The rule looks for DNS requests to sites potentially posing as SSO domains.
- [Okta Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_Query.yml)
  - Okta Logins from an IP Address not found in CrowdStrike's AIP List
- [Okta Login From CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/okta_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_FDREvent.yml)
  - Okta Logins from an IP Address not found in CrowdStrike's AIP List (crowdstrike_fdrevent table)


# D

- [Dropbox](#dropbox)
- [Duo](#duo)


## Dropbox

- [Dropbox Admin sign-in-as Session](../rules/dropbox_rules/dropbox_admin_sign_in_as_session.yml)
  - Alerts when an admin starts a sign-in-as session.
- [Dropbox Document/Folder Ownership Transfer](../rules/dropbox_rules/dropbox_ownership_transfer.yml)
  - Dropbox ownership of a document or folder has been transferred.
- [Dropbox External Share](../rules/dropbox_rules/dropbox_external_share.yml)
  - Dropbox item shared externally
- [Dropbox Linked Team Application Added](../rules/dropbox_rules/dropbox_linked_team_application_added.yml)
  - An application was linked to your Dropbox Account
- [Dropbox Many Deletes](../queries/dropbox_queries/Dropbox_Many_Deletes_Query.yml)
  - Dropbox Many Deletes
- [Dropbox Many Downloads](../queries/dropbox_queries/Dropbox_Many_Downloads_Query.yml)
  - Dropbox Many Downloads
- [Dropbox User Disabled 2FA](../rules/dropbox_rules/dropbox_user_disabled_2fa.yml)
  - Dropbox user has disabled 2fa login


## Duo

- [Duo Admin App Integration Secret Key Viewed](../rules/duo_rules/duo_admin_app_integration_secret_key_viewed.yml)
  - An administrator viewed a Secret Key for an Application Integration
- [Duo Admin Bypass Code Created](../rules/duo_rules/duo_admin_bypass_code_created.yml)
  - A Duo administrator created an MFA bypass code for an application.
- [Duo Admin Bypass Code Viewed](../rules/duo_rules/duo_admin_bypass_code_viewed.yml)
  - An administrator viewed the MFA bypass code for a user.
- [Duo Admin Create Admin](../rules/duo_rules/duo_admin_create_admin.yml)
  - A new Duo Administrator was created.
- [Duo Admin Lockout](../rules/duo_rules/duo_admin_lockout.yml)
  - Alert when a duo administrator is locked out of their account.
- [Duo Admin Marked Push Fraudulent](../rules/duo_rules/duo_admin_marked_push_fraudulent.yml)
  - A Duo push was marked fraudulent by an admin.
- [Duo Admin MFA Restrictions Updated](../rules/duo_rules/duo_admin_mfa_restrictions_updated.yml)
  - Detects changes to allowed MFA factors administrators can use to log into the admin panel.
- [Duo Admin New Admin API App Integration](../rules/duo_rules/duo_admin_new_admin_api_app_integration.yml)
  - Identifies creation of new Admin API integrations for Duo.
- [Duo Admin Policy Updated](../rules/duo_rules/duo_admin_policy_updated.yml)
  - A Duo Administrator updated a Policy, which governs how users authenticate.
- [Duo Admin SSO SAML Requirement Disabled](../rules/duo_rules/duo_admin_sso_saml_requirement_disabled.yml)
  - Detects when SAML Authentication for Administrators is marked as Disabled or Optional.
- [Duo Admin User MFA Bypass Enabled](../rules/duo_rules/duo_admin_user_mfa_bypass_enabled.yml)
  - An Administrator enabled a user to authenticate without MFA.
- [Duo User Action Reported as Fraudulent](../rules/duo_rules/duo_user_action_fraudulent.yml)
  - Alert when a user reports a Duo action as fraudulent.
- [Duo User Auth Denied For Anomalous Push](../rules/duo_rules/duo_user_anomalous_push.yml)
  - A Duo authentication was denied due to an anomalous 2FA push.
- [Duo User Bypass Code Used](../rules/duo_rules/duo_user_bypass_code_used.yml)
  - A Duo user's bypass code was used to authenticate
- [Duo User Denied For Endpoint Error](../rules/duo_rules/duo_user_endpoint_failure_multi.yml)
  - A Duo user's authentication was denied due to a suspicious error on the endpoint


# G

- [GCP](#gcp)
- [GitHub](#github)
- [GitLab](#gitlab)
- [Google Workspace](#google-workspace)


## GCP

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Exec into Pod](../rules/gcp_k8s_rules/gcp_k8s_exec_into_pod.yml)
  - Alerts when users exec into pod. Possible to specify specific projects and allowed users.
- [GCP Access Attempts Violating IAP Access Controls](../rules/gcp_http_lb_rules/gcp_access_attempts_violating_iap_access_controls.yml)
  - GCP Access Attempts Violating IAP Access Controls
- [GCP Access Attempts Violating VPC Service Controls](../rules/gcp_audit_rules/gcp_access_attempts_violating_vpc_service_controls.yml)
  - An access attempt violating VPC service controls (such as Perimeter controls) has been made.
- [GCP BigQuery Large Scan](../rules/gcp_audit_rules/gcp_bigquery_large_scan.yml)
  - Detect any BigQuery query that is doing a very large scan (> 1 GB).
- [GCP Cloud Run Service Created](../rules/gcp_audit_rules/gcp_cloud_run_service_created.yml)
  - Detects creation of new Cloud Run Service, which, if configured maliciously, may be part of the attack aimed to invoke the service and retrieve the access token.
- [GCP Cloud Run Service Created FOLLOWED BY Set IAM Policy](../correlation_rules/gcp_cloud_run_service_create_followed_by_set_iam_policy.yml)
  - Detects run.services.create method for privilege escalation in GCP. The exploit creates a new Cloud Run Service that, when invoked, returns the Service Account's access token by accessing the metadata API of the server it is running on.
- [GCP Cloud Run Set IAM Policy](../rules/gcp_audit_rules/gcp_cloud_run_set_iam_policy.yml)
  - Detects new roles granted to users to Cloud Run Services. This could potentially allow the user to perform actions within the project and its resources, which could pose a security risk.
- [GCP Cloud Storage Buckets Modified Or Deleted](../rules/gcp_audit_rules/gcp_cloud_storage_buckets_modified_or_deleted.yml)
  - Detects GCP cloud storage bucket updates and deletes.
- [GCP CloudBuild Potential Privilege Escalation](../rules/gcp_audit_rules/gcp_cloudbuild_potential_privilege_escalation.yml)
  - Detects privilege escalation attacks designed to gain access to the Cloud Build Service Account. A user with permissions to start a new build with Cloud Build can gain access to the Cloud Build Service Account and abuse it for more access to the environment.
- [GCP cloudfunctions functions create](../rules/gcp_audit_rules/gcp_cloudfunctions_functions_create.yml)
  - The Identity and Access Management (IAM) service manages authorization and authentication for a GCP environment. This means that there are very likely multiple privilege escalation methods that use the IAM service and/or its permissions.
- [GCP cloudfunctions functions update](../rules/gcp_audit_rules/gcp_cloudfunctions_functions_update.yml)
  - The Identity and Access Management (IAM) service manages authorization and authentication for a GCP environment. This means that there are very likely multiple privilege escalation methods that use the IAM service and/or its permissions.
- [GCP compute.instances.create Privilege Escalation](../rules/gcp_audit_rules/gcp_computeinstances_create_privilege_escalation.yml)
  - Detects compute.instances.create method for privilege escalation in GCP.
- [GCP Corporate Email Not Used](../rules/gcp_audit_rules/gcp_iam_corp_email.yml)
  - A Gmail account is being used instead of a corporate email
- [GCP Destructive Queries](../rules/gcp_audit_rules/gcp_destructive_queries.yml)
  - Detect any destructive BigQuery queries or jobs such as update, delete, drop, alter or truncate.
- [GCP DNS Zone Modified or Deleted](../rules/gcp_audit_rules/gcp_dns_zone_modified_or_deleted.yml)
  - Detection for GCP DNS zones that are deleted, patched, or updated.
- [GCP Firewall Rule Created](../rules/gcp_audit_rules/gcp_firewall_rule_created.yml)
  - This rule detects creations of GCP firewall rules.
- [GCP Firewall Rule Deleted](../rules/gcp_audit_rules/gcp_firewall_rule_deleted.yml)
  - This rule detects deletions of GCP firewall rules.
- [GCP Firewall Rule Modified](../rules/gcp_audit_rules/gcp_firewall_rule_modified.yml)
  - This rule detects modifications to GCP firewall rules.
- [GCP GCS IAM Permission Changes](../rules/gcp_audit_rules/gcp_gcs_iam_changes.yml)
  - Monitoring changes to Cloud Storage bucket permissions may reduce time to detect and correct permissions on sensitive Cloud Storage bucket and objects inside the bucket.
- [GCP GKE Kubernetes Cron Job Created Or Modified](../rules/gcp_k8s_rules/gcp_k8s_cron_job_created_or_modified.yml)
  - This detection monitor for any modifications or creations of a cron job in GKE. Attackers may create or modify an existing scheduled job in order to achieve cluster persistence.
- [GCP IAM Role Has Changed](../rules/gcp_audit_rules/gcp_iam_custom_role_changes.yml)
  - A custom role has been created, deleted, or updated.
- [GCP IAM serviceAccounts getAccessToken Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_service_accounts_get_access_token_privilege_escalation.yml)
  - The Identity and Access Management (IAM) service manages authorization and authentication for a GCP environment. This means that there are very likely multiple privilege escalation methods that use the IAM service and/or its permissions.
- [GCP IAM serviceAccounts signBlob](../rules/gcp_audit_rules/gcp_iam_service_accounts_sign_blob.yml)
  - The iam.serviceAccounts.signBlob permission "allows signing of arbitrary payloads" in GCP. This means we can create a signed blob that requests an access token from the Service Account we are targeting.
- [GCP IAM serviceAccounts.signJwt Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_serviceaccounts_signjwt.yml)
  - Detects iam.serviceAccounts.signJwt method for privilege escalation in GCP. This method works by signing well-formed JSON web tokens (JWTs). The script for this method will sign a well-formed JWT and request a new access token belonging to the Service Account with it.
- [GCP iam.roles.update Privilege Escalation](../rules/gcp_audit_rules/gcp_iam_roles_update_privilege_escalation.yml)
  - If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire.
- [GCP Inbound SSO Profile Created](../rules/gcp_audit_rules/gcp_inbound_sso_profile_created_or_updated.yml)
- [GCP K8s IOCActivity](../rules/gcp_k8s_rules/gcp_k8s_ioc_activity.yml)
  - This detection monitors for any kubernetes API Request originating from an Indicator of Compromise.
- [GCP K8s New Daemonset Deployed](../rules/gcp_k8s_rules/gcp_k8s_new_daemonset_deployed.yml)
  - Detects Daemonset creation in GCP Kubernetes clusters.
- [GCP K8s Pod Attached To Node Host Network](../rules/gcp_k8s_rules/gcp_k8s_pod_attached_to_node_host_network.yml)
  - This detection monitor for the creation of pods which are attached to the host's network. This allows a pod to listen to all network traffic for all deployed computer on that particular node and communicate with other compute on the network namespace. Attackers can use this to capture secrets passed in arguments or connections.
- [GCP K8S Pod Create Or Modify Host Path Volume Mount](../rules/gcp_k8s_rules/gcp_k8s_pod_create_or_modify_host_path_vol_mount.yml)
  - This detection monitors for pod creation with a hostPath volume mount. The attachment to a node's volume can allow for privilege escalation through underlying vulnerabilities or it can open up possibilities for data exfiltration or unauthorized file access. It is very rare to see this being a pod requirement.
- [GCP K8s Pod Using Host PID Namespace](../rules/gcp_k8s_rules/gcp_k8s_pod_using_host_pid_namespace.yml)
  - This detection monitors for any pod creation or modification using the host PID namespace. The Host PID namespace enables a pod and its containers to have direct access and share the same view as of the host’s processes. This can offer a powerful escape hatch to the underlying host.
- [GCP K8S Privileged Pod Created](../rules/gcp_k8s_rules/gcp_k8s_privileged_pod_created.yml)
  - Alerts when a user creates privileged pod. These particular pods have full access to the host’s namespace and devices, have the ability to exploit the kernel, have dangerous linux capabilities, and can be a powerful launching point for further attacks. In the event of a successful container escape where a user is operating with root privileges, the attacker retains this role on the node.
- [GCP K8S Service Type NodePort Deployed](../rules/gcp_k8s_rules/gcp_k8s_service_type_node_port_deployed.yml)
  - This detection monitors for any kubernetes service deployed with type node port. A Node Port service allows an attacker to expose a set of pods hosting the service to the internet by opening their port and redirecting traffic here. This can be used to bypass network controls and intercept traffic, creating a direct line to the outside network.
- [GCP Log Bucket or Sink Deleted](../rules/gcp_audit_rules/gcp_log_bucket_or_sink_deleted.yml)
  - This rule detects deletions of GCP Log Buckets or Sinks.
- [GCP Logging Settings Modified](../rules/gcp_audit_rules/gcp_logging_settings_modified.yml)
  - Detects any changes made to logging settings
- [GCP Logging Sink Modified](../rules/gcp_audit_rules/gcp_logging_sink_modified.yml)
  - This rule detects modifications to GCP Log Sinks.
- [GCP Org or Folder Policy Was Changed Manually](../rules/gcp_audit_rules/gcp_iam_org_folder_changes.yml)
  - Alert if a GCP Org or Folder Policy Was Changed Manually.
- [GCP Permissions Granted to Create or Manage Service Account Key](../rules/gcp_audit_rules/gcp_permissions_granted_to_create_or_manage_service_account_key.yml)
  - Permissions granted to impersonate a service account. This includes predefined service account IAM roles granted at the parent project, folder or organization-level.
- [GCP Resource in Unused Region](../rules/gcp_audit_rules/gcp_unused_regions.yml)
  - Adversaries may create cloud instances in unused geographic service regions in order to evade detection.
- [GCP Service Account Access Denied](../rules/gcp_audit_rules/gcp_service_account_access_denied.yml)
  - This rule detects deletions of GCP Log Buckets or Sinks.
- [GCP Service Account or Keys Created ](../rules/gcp_audit_rules/gcp_service_account_or_keys_created.yml)
  - Detects when a service account or key is created manually by a user instead of an automated workflow.
- [GCP serviceusage.apiKeys.create Privilege Escalation](../rules/gcp_audit_rules/gcp_serviceusage_apikeys_create_privilege_escalation.yml)
  - Detects serviceusage.apiKeys.create method for privilege escalation in GCP. By default, API Keys are created with no restrictions, which means they have access to the entire GCP project they were created in. We can capitalize on that fact by creating a new API key that may have more privileges than our own user.
- [GCP SQL Config Changes](../rules/gcp_audit_rules/gcp_sql_config_changes.yml)
  - Monitoring changes to Sql Instance configuration may reduce time to detect and correct misconfigurations done on sql server.
- [GCP storage hmac keys create](../rules/gcp_audit_rules/gcp_storage_hmac_keys_create.yml)
  - There is a feature of Cloud Storage, “interoperability”, that provides a way for Cloud Storage to interact with storage offerings from other cloud providers, like AWS S3. As part of that, there are HMAC keys that can be created for both Service Accounts and regular users. We can escalate Cloud Storage permissions by creating an HMAC key for a higher-privileged Service Account.
- [GCP User Added to IAP Protected Service](../rules/gcp_audit_rules/gcp_user_added_to_iap_protected_service.yml)
  - A user has been granted access to a IAP protected service.
- [GCP User Added to Privileged Group](../rules/gcp_audit_rules/gcp_user_added_to_privileged_group.yml)
  - A user was added to a group with special previleges
- [GCP VPC Flow Logs Disabled](../rules/gcp_audit_rules/gcp_vpc_flow_logs_disabled.yml)
  - VPC flow logs were disabled for a subnet.
- [GCP Workforce Pool Created or Updated](../rules/gcp_audit_rules/gcp_workforce_pool_created_or_updated.yml)
- [GCP Workload Identity Pool Created or Updated](../rules/gcp_audit_rules/gcp_workload_identity_pool_created_or_updated.yml)
- [GCP.Iam.ServiceAccountKeys.Create](../rules/gcp_audit_rules/gcp_iam_service_account_key_create.yml)
  - If your user is assigned a custom IAM role, then iam.roles.update will allow you to update the “includedPermissons” on that role. Because it is assigned to you, you will gain the additional privileges, which could be anything you desire.
- [GCP.Privilege.Escalation.By.Deployments.Create](../rules/gcp_audit_rules/gcp_privilege_escalation_by_deployments_create.yml)
  - Detects privilege escalation in GCP by taking over the deploymentsmanager.deployments.create permission
- [GCS Bucket Made Public](../rules/gcp_audit_rules/gcp_gcs_public.yml)
  - Adversaries may access data objects from improperly secured cloud storage.


## GitHub

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [GitHub Action Failed](../rules/github_rules/github_action_failed.yml)
  - A monitored github action has failed.
- [GitHub Advanced Security Change WITHOUT Repo Archived](../correlation_rules/github_advanced_security_change_not_followed_by_repo_archived.yml)
  - Identifies when advances security change was made not to archive a repo. Eliminates false positives in the Advances Security Change Rule when the repo is archived.
- [GitHub Branch Protection Disabled](../rules/github_rules/github_branch_protection_disabled.yml)
  - Disabling branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity.
- [GitHub Branch Protection Policy Override](../rules/github_rules/github_branch_policy_override.yml)
  - Bypassing branch protection controls could indicate malicious use of admin credentials in an attempt to hide activity.
- [GitHub Dependabot Vulnerability Dismissed](../rules/github_rules/github_repo_vulnerability_dismissed.yml)
  - Creates an alert if a dependabot alert is dismissed without being fixed.
- [GitHub Org Authentication Method Changed](../rules/github_rules/github_org_auth_modified.yml)
  - Detects changes to GitHub org authentication changes.
- [GitHub Org IP Allow List modified](../rules/github_rules/github_org_ip_allowlist.yml)
  - Detects changes to a GitHub Org IP Allow List
- [Github Organization App Integration Installed](../rules/github_rules/github_organization_app_integration_installed.yml)
  - An application integration was installed to your organization's Github account by someone in your organization.
- [Github Public Repository Created](../rules/github_rules/github_public_repository_created.yml)
  - A public Github repository was created.
- [GitHub Repository Archived](../rules/github_rules/github_repo_archived.yml)
  - Detects when a repository is archived.
- [GitHub Repository Collaborator Change](../rules/github_rules/github_repo_collaborator_change.yml)
  - Detects when a repository collaborator is added or removed.
- [GitHub Repository Created](../rules/github_rules/github_repo_created.yml)
  - Detects when a repository is created.
- [GitHub Repository Ruleset Modified](../rules/github_rules/github_repo_ruleset_modified.yml)
  - Disabling repository ruleset controls could indicate malicious use of admin credentials in an attempt to hide activity.
- [Github Repository Transfer](../rules/github_rules/github_repository_transfer.yml)
  - A user accepted a request to receive a transferred Github repository, a  Github repository was transferred to another repository network, or a user sent a request to transfer a repository to another user or organization.
- [GitHub Repository Visibility Change](../rules/github_rules/github_repo_visibility_change.yml)
  - Detects when an organization repository visibility changes.
- [GitHub Secret Scanning Alert Created](../rules/github_rules/github_secret_scanning_alert_created.yml)
  - GitHub detected a secret and created a secret scanning alert.
- [GitHub Security Change, includes GitHub Advanced Security](../rules/github_rules/github_advanced_security_change.yml)
  - The rule alerts when GitHub Security tools (Dependabot, Secret Scanner, etc) are disabled.
- [GitHub Team Modified](../rules/github_rules/github_team_modified.yml)
  - Detects when a team is modified in some way, such as adding a new team, deleting a team, modifying members, or a change in repository control.
- [GitHub User Access Key Created](../rules/github_rules/github_user_access_key_created.yml)
  - Detects when a GitHub user access key is created.
- [GitHub User Added or Removed from Org](../rules/github_rules/github_org_modified.yml)
  - Detects when a user is added or removed from a GitHub Org.
- [GitHub User Added to Org Moderators](../rules/github_rules/github_org_moderators_add.yml)
  - Detects when a user is added to a GitHub org's list of moderators.
- [GitHub User Initial Access to Private Repo](../rules/github_rules/github_repo_initial_access.yml)
  - Detects when a user initially accesses a private organization repository.
- [GitHub User Role Updated](../rules/github_rules/github_user_role_updated.yml)
  - Detects when a GitHub user role is upgraded to an admin or downgraded to a member
- [GitHub Web Hook Modified](../rules/github_rules/github_webhook_modified.yml)
  - Detects when a webhook is added, modified, or deleted
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Secret Exposed and not Quarantined](../correlation_rules/secret_exposed_and_not_quarantined.yml)
  - The rule detects when a GitHub Secret Scan detects an exposed secret, which is not followed by the expected quarantine operation in AWS.  When you make a repository public, or push changes to a public repository, GitHub always scans the code for secrets that match partner patterns. Public packages on the npm registry are also scanned. If secret scanning detects a potential secret, we notify the service provider who issued the secret. The service provider validates the string and then decides whether they should revoke the secret, issue a new secret, or contact you directly. Their action will depend on the associated risks to you or them.


## GitLab

- [CVE-2023-7028 - GitLab Audit Password Reset Multiple Emails](../rules/gitlab_rules/gitlab_audit_password_reset_multiple_emails.yml)
  - Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address.
- [CVE-2023-7028 - GitLab Production Password Reset Multiple Emails](../rules/gitlab_rules/gitlab_production_password_reset_multiple_emails.yml)
  - Attackers are exploiting a Critical (CVSS 10.0) GitLab vulnerability in which user account password reset emails could be delivered to an unverified email address.


## Google Workspace

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [External GSuite File Share](../rules/gsuite_reports_rules/gsuite_drive_external_share.yml)
  - An employee shared a sensitive file externally with another organization
- [Google Accessed a GSuite Resource](../rules/gsuite_activityevent_rules/gsuite_google_access.yml)
  - Google accessed one of your GSuite resources directly, most likely in response to a support incident.
- [Google Drive High Download Count](../queries/gsuite_queries/gsuite_drive_many_docs_downloaded.yml)
  - Scheduled rule for the High Google Drive Download Count query which looks for incidents of more than 10 (tunable) downloads by a user in the past day.
- [Google Workspace Admin Custom Role](../rules/gsuite_activityevent_rules/google_workspace_admin_custom_role.yml)
  - A Google Workspace administrator created a new custom administrator role.
- [Google Workspace Advanced Protection Program](../rules/gsuite_activityevent_rules/google_workspace_advanced_protection_program.yml)
  - Your organization's Google Workspace Advanced Protection Program settings were modified.
- [Google Workspace Apps Marketplace Allowlist](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_allowlist.yml)
  - Google Workspace Marketplace application allowlist settings were modified.
- [Google Workspace Apps Marketplace New Domain Application](../rules/gsuite_activityevent_rules/google_workspace_apps_marketplace_new_domain_application.yml)
  - A Google Workspace User configured a new domain application from the Google Workspace Apps Marketplace.
- [Google Workspace Apps New Mobile App Installed](../rules/gsuite_activityevent_rules/google_workspace_apps_new_mobile_app_installed.yml)
  - A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps.
- [GSuite Calendar Has Been Made Public](../rules/gsuite_activityevent_rules/gsuite_calendar_made_public.yml)
  - A User or Admin Has Modified A Calendar To Be Public
- [GSuite Device Suspicious Activity](../rules/gsuite_activityevent_rules/gsuite_mobile_device_suspicious_activity.yml)
  - GSuite reported a suspicious activity on a user's device.
- [GSuite Document External Ownership Transfer](../rules/gsuite_activityevent_rules/gsuite_doc_ownership_transfer.yml)
  - A GSuite document's ownership was transferred to an external party.
- [GSuite Drive Many Documents Deleted](../queries/gsuite_queries/gsuite_drive_many_docs_deleted.yml)
  - Scheduled rule for the GSuite Drive Many Documents Deleted query. Looks for users who have deleted more than 10 (tunable) documents the past day.
- [GSuite External Drive Document](../rules/gsuite_reports_rules/gsuite_drive_visibility_change.yml)
  - A Google drive resource became externally accessible.
- [GSuite Government Backed Attack](../rules/gsuite_activityevent_rules/gsuite_gov_attack.yml)
  - GSuite reported that it detected a government backed attack against your account.
- [GSuite Login Type](../rules/gsuite_activityevent_rules/gsuite_login_type.yml)
  - A login of a non-approved type was detected for this user.
- [Gsuite Mail forwarded to external domain](../rules/gsuite_activityevent_rules/gsuite_external_forwarding.yml)
  - A user has configured mail forwarding to an external domain
- [GSuite Many Docs Deleted Query](../queries/gsuite_queries/GSuite_Many_Docs_Deleted_Query.yml)
  - Query to search for a user deleting many documents.
- [GSuite Many Docs Downloaded Query](../queries/gsuite_queries/GSuite_Many_Docs_Downloaded_Query.yml)
  - Query to search high document download counts by users.
- [GSuite Overly Visible Drive Document](../rules/gsuite_reports_rules/gsuite_drive_overly_visible.yml)
  - A Google drive resource that is overly visible has been modified.
- [GSuite Passthrough Rule Triggered](../rules/gsuite_activityevent_rules/gsuite_passthrough_rule.yml)
  - A GSuite rule was triggered.
- [GSuite User Advanced Protection Change](../rules/gsuite_activityevent_rules/gsuite_advanced_protection.yml)
  - A user disabled advanced protection for themselves.
- [GSuite User Banned from Group](../rules/gsuite_activityevent_rules/gsuite_group_banned_user.yml)
  - A GSuite user was banned from an enterprise group by moderator action.
- [GSuite User Device Compromised](../rules/gsuite_activityevent_rules/gsuite_mobile_device_compromise.yml)
  - GSuite reported a user's device has been compromised.
- [GSuite User Device Unlock Failures](../rules/gsuite_activityevent_rules/gsuite_mobile_device_screen_unlock_fail.yml)
  - Someone failed to unlock a user's device multiple times in quick succession.
- [GSuite User Password Leaked](../rules/gsuite_activityevent_rules/gsuite_leaked_password.yml)
  - GSuite reported a user's password has been compromised, so they disabled the account.
- [GSuite User Suspended](../rules/gsuite_activityevent_rules/gsuite_user_suspended.yml)
  - A GSuite user was suspended, the account may have been compromised by a spam network.
- [GSuite User Two Step Verification Change](../rules/gsuite_activityevent_rules/gsuite_two_step_verification.yml)
  - A user disabled two step verification for themselves.
- [GSuite Workspace Calendar External Sharing Setting Change](../rules/gsuite_activityevent_rules/gsuite_workspace_calendar_external_sharing.yml)
  - A Workspace Admin Changed The Sharing Settings for Primary Calendars
- [GSuite Workspace Data Export Has Been Created](../rules/gsuite_activityevent_rules/gsuite_workspace_data_export_created.yml)
  - A Workspace Admin Has Created a Data Export
- [GSuite Workspace Gmail Default Routing Rule Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_default_routing_rule.yml)
  - A Workspace Admin Has Modified A Default Routing Rule In Gmail
- [GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_enhanced_predelivery_scanning.yml)
  - A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail.
- [GSuite Workspace Gmail Security Sandbox Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_gmail_security_sandbox_disabled.yml)
  - A Workspace Admin Has Disabled The Security Sandbox
- [GSuite Workspace Password Reuse Has Been Enabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_reuse_enabled.yml)
  - A Workspace Admin Has Enabled Password Reuse
- [GSuite Workspace Strong Password Enforcement Has Been Disabled](../rules/gsuite_activityevent_rules/gsuite_workspace_password_enforce_strong_disabled.yml)
  - A Workspace Admin Has Disabled The Enforcement Of Strong Passwords
- [GSuite Workspace Trusted Domain Allowlist Modified](../rules/gsuite_activityevent_rules/gsuite_workspace_trusted_domains_allowlist.yml)
  - A Workspace Admin Has Modified The Trusted Domains List
- [Suspicious GSuite Login](../rules/gsuite_activityevent_rules/gsuite_suspicious_logins.yml)
  - GSuite reported a suspicious login for this user.


# M

- [Microsoft365](#microsoft365)
- [MicrosoftGraph](#microsoftgraph)
- [MongoDB](#mongodb)


## Microsoft365

- [Microsoft Exchange External Forwarding](../rules/microsoft_rules/microsoft_exchange_external_forwarding.yml)
  - Detects when a user creates email forwarding rules to external organizations in Microsoft Exchange Online. This can indicate data exfiltration attempts, where an attacker sets up forwarding to collect emails outside the organization. The rule detects both mailbox forwarding (Set-Mailbox) and inbox rules (New-InboxRule).The detection includes: 1. External organization forwarding based on domain comparison 2. Suspicious forwarding patterns like:   - Forwarding without keeping a copy   - Deleting messages after forwarding   - Stopping rule processing after forwarding3. Multiple forwarding destinations 4. Various forwarding methods (SMTP, redirect, forward as attachment)
- [Microsoft365 Brute Force Login by User](../rules/microsoft_rules/microsoft365_brute_force_login_by_user.yml)
  - A Microsoft365 user was denied login access several times
- [Microsoft365 External Document Sharing](../rules/microsoft_rules/microsoft365_external_sharing.yml)
  - Document shared externally
- [Microsoft365 MFA Disabled](../rules/microsoft_rules/microsoft365_mfa_disabled.yml)
  - A user's MFA has been removed


## MicrosoftGraph

- [Microsoft Graph Passthrough](../rules/microsoft_rules/microsoft_graph_passthrough.yml)
  - The Microsoft Graph security API federates queries to all onboarded security providers, including Azure AD Identity Protection, Microsoft 365, Microsoft Defender (Cloud, Endpoint, Identity) and Microsoft Sentinel


## MongoDB

- [MongoDB 2FA Disabled](../rules/mongodb_rules/mongodb_2fa_disabled.yml)
  - 2FA was disabled.
- [MongoDB access allowed from anywhere](../rules/mongodb_rules/mongodb_access_allowed_from_anywhere.yml)
  - Atlas only allows client connections to the database deployment from entries in the project's IP access list. This rule detects when 0.0.0.0/0 is added to that list, which allows access from anywhere.
- [MongoDB Atlas API Key Created](../rules/mongodb_rules/mongodb_atlas_api_key_created.yml)
  - A MongoDB Atlas api key's access list was updated
- [MongoDB External User Invited](../rules/mongodb_rules/mongodb_external_user_invited.yml)
  - An external user has been invited to a MongoDB org.
- [MongoDB External User Invited (no config)](../rules/mongodb_rules/mongodb_external_user_invited_no_config.yml)
  - An external user has been invited to a MongoDB org (no config).
- [MongoDB Identity Provider Activity](../rules/mongodb_rules/mongodb_identity_provider_activity.yml)
  - Changes to identity provider settings are privileged activities that should be carefully audited.  Attackers may add or change IDP integrations to gain persistence to environments
- [MongoDB logging toggled](../rules/mongodb_rules/mongodb_logging_toggled.yml)
  - MongoDB logging toggled
- [MongoDB org membership restriction disabled](../rules/mongodb_rules/mongodb_org_membership_restriction_disabled.yml)
  - You can configure Atlas to require API access lists at the organization level. When you enable IP access list for the Atlas Administration API, all API calls in that organization must originate from a valid entry in the associated Atlas Administration API key access list. This rule detects when IP access list is disabled
- [MongoDB security alerts disabled or deleted](../rules/mongodb_rules/mongodb_alerting_disabled.yml)
  - MongoDB provides security alerting policies for notifying admins when certain conditions are met. This rule detects when these policies are disabled or deleted.
- [MongoDB user roles changed](../rules/mongodb_rules/mongodb_user_roles_changed.yml)
  - User roles changed.
- [MongoDB user was created or deleted](../rules/mongodb_rules/mongodb_user_created_or_deleted.yml)
  - User was created or deleted.


# N

- [Netskope](#netskope)
- [Notion](#notion)


## Netskope

- [Action Performed by Netskope Personnel](../rules/netskope_rules/netskope_personnel_action.yml)
  - An action was performed by Netskope personnel.
- [Admin logged out because of successive login failures](../rules/netskope_rules/netskope_admin_logged_out.yml)
  - An admin was logged out because of successive login failures.
- [An administrator account was created, deleted, or modified.](../rules/netskope_rules/netskope_admin_user_change.yml)
  - An administrator account was created, deleted, or modified.
- [Netskope Many Objects Deleted](../rules/netskope_rules/netskope_many_deletes.yml)
  - A user deleted a large number of objects in a short period of time.
- [Netskope Many Unauthorized API Calls](../rules/netskope_rules/netskope_unauthorized_api_calls.yml)
  - Many unauthorized API calls were observed for a user in a short period of time.


## Notion

- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
  - A user has subsequent logins from two geographic locations that are very far apart
- [Notion Audit Log Exported](../rules/notion_rules/notion_workspace_audit_log_exported.yml)
  - A Notion User exported audit logs for your organization’s workspace.
- [Notion Login FOLLOWED BY AccountChange](../correlation_rules/notion_login_followed_by_account_change.yml)
  - A Notion User logged in then changed their account details.
- [Notion Login From Blocked IP](../rules/notion_rules/notion_login_from_blocked_ip.yml)
  - A user attempted to access Notion from a blocked IP address. Note: before deployinh, make sure to add Rule Filters checking if event.ip_address is in a certain CIDR range(s).
- [Notion Login from New Location](../rules/notion_rules/notion_login_from_new_location.yml)
  - A Notion User logged in from a new location.
- [Notion Many Pages Deleted](../queries/notion_queries/notion_many_pages_deleted_sched.yml)
  - A Notion User deleted multiple pages, which were not created or restored from the trash within the same hour.
- [Notion Many Pages Deleted Query](../queries/notion_queries/notion_many_pages_deleted_query.yml)
  - A Notion User deleted multiple pages, which were not created or restored from the trash within the same hour.
- [Notion Many Pages Exported](../rules/notion_rules/notion_many_pages_exported.yml)
  - A Notion User exported multiple pages.
- [Notion Page API Permissions Changed](../rules/notion_rules/notion_page_accessible_to_api.yml)
  - A new API integration was added to a Notion page, or it's permissions were changed.
- [Notion Page Guest Permissions Changed](../rules/notion_rules/notion_page_accessible_to_guests.yml)
  - The external guest permissions for a Notion page have been altered.
- [Notion Page Published to Web](../rules/notion_rules/notion_page_shared_to_web.yml)
  - A Notion User published a page to the web.
- [Notion SAML SSO Configuration Changed](../rules/notion_rules/notion_workspace_settings_enforce_saml_sso_config_updated.yml)
  - A Notion User changed settings to enforce SAML SSO configurations for your organization.
- [Notion SCIM Token Generated](../rules/notion_rules/notion_scim_token_generated.yml)
  - A Notion User generated a SCIM token.
- [Notion Sharing Settings Updated](../rules/notion_rules/notion_sharing_settings_updated.yml)
  - A Notion User enabled sharing for a Workspace or Teamspace.
- [Notion Teamspace Owner Added](../rules/notion_rules/notion_teamspace_owner_added.yml)
  - A Notion User was added as a Teamspace owner.
- [Notion Workspace Exported](../rules/notion_rules/notion_workspace_exported.yml)
  - A Notion User exported an existing workspace.
- [Notion Workspace public page added](../rules/notion_rules/notion_workspace_settings_public_homepage_added.yml)
  - A Notion page was set to public in your worksace.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


# O

- [OCSF](#ocsf)
- [Okta](#okta)
- [OneLogin](#onelogin)
- [OnePassword](#onepassword)
- [Osquery](#osquery)


## OCSF

- [AWS DNS Crypto Domain](../rules/aws_vpc_flow_rules/aws_dns_crypto_domain.yml)
  - Identifies clients that may be performing DNS lookups associated with common currency mining pools.
- [AWS VPC Healthy Log Status](../rules/aws_vpc_flow_rules/aws_vpc_healthy_log_status.yml)
  - Checks for the log status `SKIPDATA`, which indicates that data was lost either to an internal server error or due to capacity constraints.
- [VPC Flow Logs Inbound Port Allowlist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_allowlist.yml)
  - VPC Flow Logs observed inbound traffic violating the port allowlist.
- [VPC Flow Logs Inbound Port Blocklist](../rules/aws_vpc_flow_rules/aws_vpc_inbound_traffic_port_blocklist.yml)
  - VPC Flow Logs observed inbound traffic violating the port blocklist.
- [VPC Flow Logs Unapproved Outbound DNS Traffic](../rules/aws_vpc_flow_rules/aws_vpc_unapproved_outbound_dns.yml)
  - Alerts if outbound DNS traffic is detected to a non-approved DNS server. DNS is often used as a means to exfiltrate data or perform command and control for compromised hosts. All DNS traffic should be routed through internal DNS servers or trusted 3rd parties.


## Okta

- [AWS Console Sign-In NOT PRECEDED BY Okta Redirect](../correlation_rules/aws_console_sign-in_without_okta.yml)
  - A user has logged into the AWS console without authenticating via Okta.  This rule requires AWS SSO via Okta and both log sources configured.
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Impossible Travel for Login Action](../rules/standard_rules/impossible_travel_login.yml)
  - A user has subsequent logins from two geographic locations that are very far apart
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Okta Admin Access Granted](../queries/okta_queries/okta_admin_access_granted.yml)
  - Audit instances of admin access granted in your okta tenant
- [Okta Admin Role Assigned](../rules/okta_rules/okta_admin_role_assigned.yml)
  - A user has been granted administrative privileges in Okta
- [Okta AiTM Phishing Attempt Blocked by FastPass](../rules/okta_rules/okta_phishing_attempt_blocked_by_fastpass.yml)
  - Okta FastPass detected a user targeted by attackers wielding real-time (AiTM) proxies.
- [Okta API Key Created](../rules/okta_rules/okta_api_key_created.yml)
  - A user created an API Key in Okta
- [Okta API Key Revoked](../rules/okta_rules/okta_api_key_revoked.yml)
  - A user has revoked an API Key in Okta
- [Okta App Refresh Access Token Reuse](../rules/okta_rules/okta_app_refresh_access_token_reuse.yml)
  - When a client wants to renew an access token, it sends the refresh token with the access token request to the /token Okta endpoint.Okta validates the incoming refresh token, issues a new set of tokens and invalidates the refresh token that was passed with the initial request.This detection alerts when a previously used refresh token is used again with the token request
- [Okta App Unauthorized Access Attempt](../rules/okta_rules/okta_app_unauthorized_access_attempt.yml)
  - Detects when a user is denied access to an Okta application
- [Okta Cleartext Passwords Extracted via SCIM Application](../rules/okta_rules/okta_password_extraction_via_scim.yml)
  - An application admin has extracted cleartext user passwords via SCIM app. Malcious actors can extract plaintext passwords by creating a SCIM application under their control and configuring it to sync passwords from Okta.
- [Okta Group Admin Role Assigned](../rules/okta_rules/okta_group_admin_role_assigned.yml)
  - Detect when an admin role is assigned to a group
- [Okta HAR File IOCs](../queries/okta_queries/okta_harfile_iocs.yml)
  - https://sec.okta.com/harfiles
- [Okta Identity Provider Created or Modified](../rules/okta_rules/okta_idp_create_modify.yml)
  - A new 3rd party Identity Provider has been created or modified. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target.
- [Okta Identity Provider Sign-in](../rules/okta_rules/okta_idp_signin.yml)
  - A user has signed in using a 3rd party Identity Provider. Attackers have been observed configuring a second Identity Provider to act as an "impersonation app" to access applications within the compromised Org on behalf of other users. This second Identity Provider, also controlled by the attacker, would act as a “source” IdP in an inbound federation relationship (sometimes called “Org2Org”) with the target. From this “source” IdP, the threat actor manipulated the username parameter for targeted users in the second “source” Identity Provider to match a real user in the compromised “target” Identity Provider. This provided the ability to Single sign-on (SSO) into applications in the target IdP as the targeted user. Do not use this rule if your organization uses legitimate 3rd-party Identity Providers.
- [Okta Investigate MFA and Password resets](../queries/okta_queries/okta_mfa_password_reset_audit.yml)
  - Investigate Password and MFA resets for the last 7 days
- [Okta Investigate Session ID Activity](../queries/okta_queries/okta_session_id_audit.yml)
  - Search for activity related to a specific SessionID in Okta panther_logs.okta_systemlog
- [Okta Investigate User Activity](../queries/okta_queries/okta_activity_audit.yml)
  - Audit user activity across your environment. Customize to filter on specific users, time ranges, etc
- [Okta Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_Query.yml)
  - Okta Logins from an IP Address not found in CrowdStrike's AIP List
- [Okta Login From CrowdStrike Unmanaged Device (crowdstrike_fdrevent table)](../queries/okta_queries/Okta_Login_From_CrowdStrike_Unmanaged_Device_FDREvent.yml)
  - Okta Logins from an IP Address not found in CrowdStrike's AIP List (crowdstrike_fdrevent table)
- [Okta MFA Globally Disabled](../rules/okta_rules/okta_admin_disabled_mfa.yml)
  - An admin user has disabled the MFA requirement for your Okta account
- [Okta New Behaviors Acessing Admin Console](../rules/okta_rules/okta_new_behavior_accessing_admin_console.yml)
  - New Behaviors Observed while Accessing Okta Admin Console. A user attempted to access the Okta Admin Console from a new device with a new IP.
- [Okta Org2Org application created of modified](../rules/okta_rules/okta_org2org_creation_modification.yml)
  - An Okta Org2Org application has been created or modified. Okta's Org2Org applications instances are used to push and match users from one Okta organization to another. A malicious actor can add an Org2Org application instance and create a user in the source organization (controlled by the attacker) with the same identifier as a Super Administrator in the target organization.
- [Okta Password Accessed](../rules/okta_rules/okta_password_accessed.yml)
  - User accessed another user's application password
- [Okta Potentially Stolen Session](../rules/okta_rules/okta_potentially_stolen_session.yml)
  - This rule looks for the same session being used from two devices, indicating a compromised session token.
- [Okta Rate Limits](../rules/okta_rules/okta_rate_limits.yml)
  - Potential DoS/Bruteforce attack or hitting limits (system degradation)
- [Okta Sign-In from VPN Anonymizer](../rules/okta_rules/okta_anonymizing_vpn_login.yml)
  - A user is attempting to sign-in to Okta from a known VPN anonymizer.  The threat actor would access the compromised account using anonymizing proxy services.
- [Okta Support Access](../queries/okta_queries/okta_support_access.yml)
  - Show instances that Okta support was granted to your account
- [Okta Support Access Granted](../rules/okta_rules/okta_account_support_access.yml)
  - An admin user has granted access to Okta Support to your account
- [Okta Support Reset Credential](../rules/okta_rules/okta_support_reset.yml)
  - A Password or MFA factor was reset by Okta Support
- [Okta ThreatInsight Security Threat Detected](../rules/okta_rules/okta_threatinsight_security_threat_detected.yml)
  - Okta ThreatInsight identified request from potentially malicious IP address
- [Okta User Account Locked](../rules/okta_rules/okta_user_account_locked.yml)
  - An Okta user has locked their account.
- [Okta User MFA Factor Suspend](../rules/okta_rules/okta_user_mfa_factor_suspend.yml)
  - Suspend factor or authenticator enrollment method for user.
- [Okta User MFA Own Reset](../rules/okta_rules/okta_user_mfa_reset.yml)
  - User has reset one of their own MFA factors
- [Okta User MFA Reset All](../rules/okta_rules/okta_user_mfa_reset_all.yml)
  - All MFA factors have been reset for a user.
- [Okta User Reported Suspicious Activity](../rules/okta_rules/okta_user_reported_suspicious_activity.yml)
  - Suspicious Activity Reporting provides an end user with the option to report unrecognized activity from an account activity email notification.This detection alerts when a user marks the raised activity as suspicious.
- [Okta Username Above 52 Characters Security Advisory](../queries/okta_queries/okta_52_char_username_threat_hunt.yml)
  - On October 30, 2024, a vulnerability was internally identified in generating the cache key for AD/LDAP DelAuth. The Bcrypt algorithm was used to generate the cache key where we hash a combined string of userId + username + password. Under a specific set of conditions, listed below, this could allow users to authenticate by providing the username with the stored cache key of a previous successful authentication. Customers meeting the pre-conditions should investigate their Okta System Log for unexpected authentications from usernames greater than 52 characters between the period of July 23rd, 2024 to October 30th, 2024. https://trust.okta.com/security-advisories/okta-ad-ldap-delegated-authentication-username/
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## OneLogin

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
  - A new account was created
- [OneLogin Active Login Activity](../rules/onelogin_rules/onelogin_active_login_activity.yml)
  - Multiple user accounts logged in from the same ip address.
- [OneLogin Authentication Factor Removed](../rules/onelogin_rules/onelogin_remove_authentication_factor.yml)
  - A user removed an authentication factor or otp device.
- [OneLogin Failed High Risk Login](../rules/onelogin_rules/onelogin_high_risk_failed_login.yml)
  - A OneLogin attempt with a high risk factor (>50) resulted in a failed authentication.
- [OneLogin High Risk Failed Login FOLLOWED BY Successful Login](../correlation_rules/onelogin_successful_login_after_high_risk_failed_login.yml)
  - A OneLogin user successfully logged in after a failed high-risk login attempt.
- [OneLogin Multiple Accounts Deleted](../rules/onelogin_rules/onelogin_threshold_accounts_deleted.yml)
  - Possible Denial of Service detected. Threshold for user account deletions exceeded.
- [OneLogin Multiple Accounts Modified](../rules/onelogin_rules/onelogin_threshold_accounts_modified.yml)
  - Possible Denial of Service detected. Threshold for user account password changes exceeded.
- [OneLogin Password Access](../rules/onelogin_rules/onelogin_password_accessed.yml)
  - User accessed another user's application password
- [OneLogin Unauthorized Access](../rules/onelogin_rules/onelogin_unauthorized_access.yml)
  - A OneLogin user was denied access to an app more times than the configured threshold.
- [OneLogin User Assumed Another User](../rules/onelogin_rules/onelogin_user_assumed.yml)
  - User assumed another user account
- [OneLogin User Locked](../rules/onelogin_rules/onelogin_user_account_locked.yml)
  - User locked or suspended from their account.
- [OneLogin User Password Changed](../rules/onelogin_rules/onelogin_password_changed.yml)
  - A user password was updated.
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks


## OnePassword

- [1Password Login From CrowdStrike Unmanaged Device](../queries/crowdstrike_queries/onepassword_login_from_crowdstrike_unmanaged_device.yml)
  - Detects 1Password Logins from IP addresses not found in CrowdStrike's AIP list. May indicate unmanaged device being used, or faulty CrowdStrike Sensor.
- [1Password Login From CrowdStrike Unmanaged Device Query](../queries/crowdstrike_queries/onepass_login_from_crowdstrike_unmanaged_device_query.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List.
- [1Password Login From CrowdStrike Unmanaged Device Query (crowdstrike_fdrevent table)](../queries/onepassword_queries/onepass_login_from_crowdstrike_unmanaged_device_FDREvent.yml)
  - Looks for OnePassword Logins from IP Addresses that aren't seen in CrowdStrike's AIP List. (crowdstrike_fdrevent table)
- [BETA - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_lut_sensitive_item_access.yml)
  - Alerts when a user defined list of sensitive items in 1Password is accessed
- [Brute Force By IP](../rules/standard_rules/brute_force_by_ip.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Brute Force By User](../rules/standard_rules/brute_force_by_user.yml)
  - An actor user was denied login access more times than the configured threshold.
- [Configuration Required - Sensitive 1Password Item Accessed](../rules/onepassword_rules/onepassword_sensitive_item_access.yml)
  - Alerts when a user defined list of sensitive items in 1Password is accessed
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Unusual 1Password Client Detected](../rules/onepassword_rules/onepassword_unusual_client.yml)
  - Detects when unusual or undesirable 1Password clients access your 1Password account


## Osquery

- [A backdoored version of XZ or liblzma is vulnerable to CVE-2024-3094](../rules/osquery_rules/osquery_linux_mac_vulnerable_xz_liblzma.yml)
  - Detects vulnerable versions of XZ and liblzma on Linux and MacOS using Osquery logs. Versions 5.6.0 and 5.6.1 of xz and liblzma are most likely vulnerable to backdoor exploit. Vuln management pack must be enabled: https://github.com/osquery/osquery/blob/master/packs/vuln-management.conf
- [A Login from Outside the Corporate Office](../rules/osquery_rules/osquery_linux_logins_non_office.yml)
  - A system has been logged into from a non approved IP space.
- [AWS command executed on the command line](../rules/osquery_rules/osquery_linux_aws_commands.yml)
  - An AWS command was executed on a Linux instance
- [MacOS ALF is misconfigured](../rules/osquery_rules/osquery_mac_application_firewall.yml)
  - The application level firewall blocks unwanted network connections made to your computer from other computers on your network.
- [MacOS Keyboard Events](../rules/osquery_rules/osquery_mac_osx_attacks_keyboard_events.yml)
  - A Key Logger has potentially been detected on a macOS system
- [macOS Malware Detected with osquery](../rules/osquery_rules/osquery_mac_osx_attacks.yml)
  - Malware has potentially been detected on a macOS system
- [Osquery Agent Outdated](../rules/osquery_rules/osquery_outdated.yml)
  - Keep track of osquery versions, current is 5.10.2.
- [OSQuery Detected SSH Listener](../rules/osquery_rules/osquery_ssh_listener.yml)
  - Check if SSH is listening in a non-production environment. This could be an indicator of persistent access within an environment.
- [OSQuery Detected Unwanted Chrome Extensions](../rules/osquery_rules/osquery_mac_unwanted_chrome_extensions.yml)
  - Monitor for chrome extensions that could lead to a credential compromise.
- [OSQuery Reports Application Firewall Disabled](../rules/osquery_rules/osquery_mac_enable_auto_update.yml)
  - Verifies that MacOS has automatic software updates enabled.
- [OSSEC Rootkit Detected via Osquery](../rules/osquery_rules/osquery_ossec.yml)
  - Checks if any results are returned for the Osquery OSSEC Rootkit pack.
- [Suspicious cron detected](../rules/osquery_rules/osquery_suspicious_cron.yml)
  - A suspicious cron has been added
- [Unsupported macOS version](../rules/osquery_rules/osquery_outdated_macos.yml)
  - Check that all laptops on the corporate environment are on a version of MacOS supported by IT.


# P

- [Panther](#panther)
- [PushSecurity](#pushsecurity)


## Panther

- [A User Role with Sensitive Permissions has been Created](../rules/panther_audit_rules/panther_sensitive_role_created.yml)
  - A Panther user role has been created that contains admin level permissions.
- [A User's Panther Account was Modified](../rules/panther_audit_rules/panther_user_modified.yml)
  - A Panther user's role has been modified. This could mean password, email, or role has changed for the user.
- [Detection content has been deleted from Panther](../rules/panther_audit_rules/panther_detection_deleted.yml)
  - Detection content has been removed from Panther.
- [Panther SAML configuration has been modified](../rules/panther_audit_rules/panther_saml_modified.yml)
  - An Admin has modified Panther's SAML configuration.
- [Snowflake User Daily Query Volume Spike - Threat Hunting](../queries/snowflake_queries/snowflake_user_query_volume_spike_threat_hunting.yml)
  - This query returns the most voluminous queries executed by a specific user over the past 48 hours.


## PushSecurity

- [Push Security App Banner Acknowledged](../rules/push_security_rules/push_security_app_banner_acknowledged.yml)
- [Push Security Authorized IdP Login](../rules/push_security_rules/push_security_authorized_idp_login.yml)
  - Login to application with unauthorized identity provider which could indicate a SAMLjacking attack.
- [Push Security New App Detected](../rules/push_security_rules/push_security_new_app_detected.yml)
- [Push Security New SaaS Account Created](../rules/push_security_rules/push_security_new_saas_account_created.yml)
- [Push Security Open Security Finding](../rules/push_security_rules/push_security_open_security_finding.yml)
- [Push Security Phishable MFA Method](../rules/push_security_rules/push_security_phishable_mfa_method.yml)
- [Push Security Phishing Attack](../rules/push_security_rules/push_security_phishing_attack.yml)
- [Push Security SaaS App MFA Method Changed](../rules/push_security_rules/push_security_mfa_method_changed.yml)
  - MFA method on SaaS app changed
- [Push Security Unauthorized IdP Login](../rules/push_security_rules/push_security_unauthorized_idp_login.yml)
  - Login to application with unauthorized identity provider which could indicate a SAMLjacking attack.


# S

- [Salesforce](#salesforce)
- [SentinelOne](#sentinelone)
- [Slack](#slack)
- [Snowflake](#snowflake)
- [Snyk](#snyk)
- [Sublime](#sublime)
- [Suricata](#suricata)


## Salesforce

- [Salesforce Admin Login As User](../rules/salesforce_rules/salesforce_admin_login_as_user.yml)
  - Salesforce detection that alerts when an admin logs in as another user.


## SentinelOne

- [SentinelOne Alert Passthrough](../rules/sentinelone_rules/sentinelone_alert_passthrough.yml)
  - SentinelOne Alert Passthrough
- [SentinelOne Threats](../rules/sentinelone_rules/sentinelone_threats.yml)
  - Passthrough SentinelOne Threats


## Slack

- [Slack Anomaly Detected](../rules/slack_rules/slack_passthrough_anomaly.yml)
  - Passthrough for anomalies detected by Slack
- [Slack App Access Expanded](../rules/slack_rules/slack_app_access_expanded.yml)
  - Detects when a Slack App has had its permission scopes expanded
- [Slack App Added](../rules/slack_rules/slack_app_added.yml)
  - Detects when a Slack App has been added to a workspace
- [Slack App Removed](../rules/slack_rules/slack_app_removed.yml)
  - Detects when a Slack App has been removed
- [Slack Denial of Service](../rules/slack_rules/slack_application_dos.yml)
  - Detects when slack admin invalidates user session(s). If it happens more than once in a 24 hour period it can lead to DoS
- [Slack DLP Modified](../rules/slack_rules/slack_dlp_modified.yml)
  - Detects when a Data Loss Prevention (DLP) rule has been deactivated or a violation has been deleted
- [Slack EKM Config Changed](../rules/slack_rules/slack_ekm_config_changed.yml)
  - Detects when the logging settings for a workspace's EKM configuration has changed
- [Slack EKM Slackbot Unenrolled](../rules/slack_rules/slack_ekm_slackbot_unenrolled.yml)
  - Detects when a workspace is longer enrolled in EKM
- [Slack EKM Unenrolled](../rules/slack_rules/slack_ekm_unenrolled.yml)
  - Detects when a workspace is no longer enrolled or managed by EKM
- [Slack IDP Configuration Changed](../rules/slack_rules/slack_idp_configuration_change.yml)
  - Detects changes to the identity provider (IdP) configuration for Slack organizations.
- [Slack Information Barrier Modified](../rules/slack_rules/slack_information_barrier_modified.yml)
  - Detects when a Slack information barrier is deleted/updated
- [Slack Intune MDM Disabled](../rules/slack_rules/slack_intune_mdm_disabled.yml)
  - Detects the disabling of Microsoft Intune Enterprise MDM within Slack
- [Slack Legal Hold Policy Modified](../rules/slack_rules/slack_legal_hold_policy_modified.yml)
  - Detects changes to configured legal hold policies
- [Slack MFA Settings Changed](../rules/slack_rules/slack_mfa_settings_changed.yml)
  - Detects changes to Multi-Factor Authentication requirements
- [Slack Organization Created](../rules/slack_rules/slack_org_created.yml)
  - Detects when a Slack organization is created
- [Slack Organization Deleted](../rules/slack_rules/slack_org_deleted.yml)
  - Detects when a Slack organization is deleted
- [Slack Potentially Malicious File Shared](../rules/slack_rules/slack_potentially_malicious_file_shared.yml)
  - Detects when a potentially malicious file is shared within Slack
- [Slack Private Channel Made Public](../rules/slack_rules/slack_private_channel_made_public.yml)
  - Detects when a channel that was previously private is made public
- [Slack Service Owner Transferred](../rules/slack_rules/slack_service_owner_transferred.yml)
  - Detects transferring of service owner on request from primary owner
- [Slack SSO Settings Changed](../rules/slack_rules/slack_sso_settings_changed.yml)
  - Detects changes to Single Sign On (SSO) restrictions
- [Slack User Privilege Escalation](../rules/slack_rules/slack_user_privilege_escalation.yml)
  - Detects when a Slack user gains escalated privileges
- [Slack User Privileges Changed to User](../rules/slack_rules/slack_privilege_changed_to_user.yml)
  - Detects when a Slack account is changed to User from an elevated role.


## Snowflake

- [Snowflake Account Admin Granted](../queries/snowflake_queries/snowflake_account_admin_assigned.yml)
  - Detect when account admin is granted.
- [Snowflake Brute Force Attacks by IP](../queries/snowflake_queries/snowflake_brute_force_ip.yml)
  - Detect brute force attacks by monitoring for failed logins from the same IP address
- [Snowflake Brute Force Attacks by User](../rules/snowflake_rules/snowflake_stream_brute_force_by_username.yml)
  - Detect brute force attacks by monitorign failed logins from the same IP address
- [Snowflake Brute Force Attacks by Username](../queries/snowflake_queries/snowflake_brute_force_username.yml)
  - Detect brute force attacks by monitoring for failed logins by the same username
- [Snowflake Brute Force Login Success](../correlation_rules/snowflake_potential_brute_force_success.yml)
  - Detecting brute force activity and reporting when a user has incorrectly logged in multiple times and then had a successful login.
- [Snowflake Client IP](../queries/snowflake_queries/snowflake_0108977_ip.yml)
  - Monitor for malicious IPs interacting with Snowflake as part of ongoing cyber threat activity reported May 31st, 2024
- [Snowflake Configuration Drift](../queries/snowflake_queries/snowflake_0108977_configuration_drift.yml)
  - Monitor for configuration drift made by malicious actors as part of ongoing cyber threat activity reported May 31st, 2024
- [Snowflake Data Exfiltration](../correlation_rules/snowflake_data_exfiltration.yml)
  - In April 2024, Mandiant received threat intelligence on database records that were subsequently determined to have originated from a victim’s Snowflake instance. Mandiant notified the victim, who then engaged Mandiant to investigate suspected data theft involving their Snowflake instance. During this investigation, Mandiant determined that the organization’s Snowflake instance had been compromised by a threat actor using credentials previously stolen via infostealer malware. The threat actor used these stolen credentials to access the customer’s Snowflake instance and ultimately exfiltrate valuable data. At the time of the compromise, the account did not have multi-factor authentication (MFA) enabled.
- [Snowflake External Data Share](../rules/snowflake_rules/snowflake_stream_external_shares.yml)
  - Detect when an external share has been initiated from one source cloud to another target cloud.
- [Snowflake External Share](../queries/snowflake_queries/snowflake_external_shares.yml)
  - Detect when an external share has been initiated from one source cloud to another target cloud.
- [Snowflake File Downloaded](../queries/snowflake_queries/snowflake_file_downloaded_signal.yml)
  - A file was downloaded from a stage
- [Snowflake Grant to Public Role](../rules/snowflake_rules/snowflake_stream_public_role_grant.yml)
  - Detect additional grants to the public role.
- [Snowflake Login Without MFA](../queries/snowflake_queries/snowflake_login_without_mfa.yml)
  - Detect snowflake logins without multifactor authentication
- [Snowflake Multiple Failed Logins Followed By Success](../queries/snowflake_queries/snowflake_multiple_failed_logins_followed_by_success.yml)
  - Detecting brute force activity and reporting when a user has incorrectly logged in multiple times and then had a successful login.
- [Snowflake Successful Login](../rules/snowflake_rules/snowflake_stream_login_success.yml)
  - Track successful login signals for correlation.
- [Snowflake Table Copied Into Stage](../queries/snowflake_queries/snowflake_table_copied_into_stage_signal.yml)
  - A table was copied into a stage
- [Snowflake Temporary Stage Created](../queries/snowflake_queries/snowflake_temp_stage_created_signal.yml)
  - A temporary stage was created
- [Snowflake User Access](../queries/snowflake_queries/snowflake_0109877_suspected_user_access.yml)
  - Return sessions of suspected clients as part of ongoing cyber threat activity reported May 31st, 2024
- [Snowflake User Created](../queries/snowflake_queries/snowflake_user_created.yml)
  - Detect new users created in snowflake
- [Snowflake User Daily Query Volume Spike](../queries/snowflake_queries/snowflake_user_query_volume_spike_query.yml)
  - Returns instances where a user's cumulative daily query volume is much larger than normal. Could indicate exfiltration attempts.
- [Snowflake User Daily Query Volume Spike - Threat Hunting](../queries/snowflake_queries/snowflake_user_query_volume_spike_threat_hunting.yml)
  - This query returns the most voluminous queries executed by a specific user over the past 48 hours.
- [Snowflake User Enabled](../queries/snowflake_queries/snowflake_user_enabled.yml)
  - Detect users being re-enabled in your environment
- [Snowflake user with key-based auth logged in with password auth](../queries/snowflake_queries/snowflake_key_user_password_login.yml)
  - Detect when a user that has key-based authentication configured logs in with a password


## Snyk

- [Snyk Miscellaneous Settings](../rules/snyk_rules/snyk_misc_settings.yml)
  - Detects when Snyk settings that lack a clear security impact are changed
- [Snyk Org or Group Settings Change](../rules/snyk_rules/snyk_ou_change.yml)
  - Detects when Snyk Group or Organization Settings are changed.
- [Snyk Org Settings](../rules/snyk_rules/snyk_org_settings.yml)
  - Detects when Snyk Organization settings, like Integrations and Webhooks, are changed
- [Snyk Project Settings](../rules/snyk_rules/snyk_project_settings.yml)
  - Detects when Snyk Project settings are changed
- [Snyk Role Change](../rules/snyk_rules/snyk_role_change.yml)
  - Detects when Snyk Roles are changed
- [Snyk Service Account Change](../rules/snyk_rules/snyk_svcacct_change.yml)
  - Detects when Snyk Service Accounts are changed
- [Snyk System External Access Settings Changed](../rules/snyk_rules/snyk_system_externalaccess.yml)
  - Detects when Snyk Settings that control access for external parties have been changed.
- [Snyk System Policy Settings Changed](../rules/snyk_rules/snyk_system_policysetting.yml)
  - Detects Snyk Policy Settings have been changed. Policies define Snyk's behavior when encountering security and licensing issues.
- [Snyk System SSO Settings Changed](../rules/snyk_rules/snyk_system_sso.yml)
  - Detects Snyk SSO Settings have been changed. The reference URL from Snyk indicates that these events are likely to originate exclusively from Snyk Support.
- [Snyk User Management](../rules/snyk_rules/snyk_user_mgmt.yml)
  - Detects when Snyk Users are changed


## Sublime

- [Sublime Flagged an Email](../rules/sublime_rules/sublime_message_flagged.yml)
  - Sublime flagged some messages as suspicious.
- [Sublime Mailbox Deactivated](../rules/sublime_rules/sublime_mailboxes_deactivated.yml)
  - A Sublime User disabled some mailbox(es).
- [Sublime Message Source Deleted Or Deactivated](../rules/sublime_rules/sublime_message_source_deleted_or_deactivated.yml)
  - A Sublime User disabled or deleted some message source(s).
- [Sublime Rules Deleted Or Deactivated](../rules/sublime_rules/sublime_rules_deleted_or_deactivated.yml)
  - A Sublime User disabled or deleted some rule(s).


## Suricata

- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)
  - The rule looks for DNS requests to sites potentially posing as SSO domains.


# T

- [Tailscale](#tailscale)
- [Teleport](#teleport)
- [ThinkstCanary](#thinkstcanary)
- [Tines](#tines)
- [Tracebit](#tracebit)


## Tailscale

- [Tailscale HTTPS Disabled](../rules/tailscale_rules/tailscale_https_disabled.yml)
  - A Tailscale User disabled HTTPS settings in your organization's tenant.
- [Tailscale Machine Approval Requirements Disabled](../rules/tailscale_rules/tailscale_machine_approval_requirements_disabled.yml)
  - A Tailscale User disabled machine approval requirement settings in your organization's tenant. This means devices can access your network without requiring approval.
- [Tailscale Magic DNS Disabled](../rules/tailscale_rules/tailscale_magicdns_disabled.yml)
  - A Tailscale User disabled magic dns settings in your organization's tenant.


## Teleport

- [A long-lived cert was created](../rules/gravitational_teleport_rules/teleport_long_lived_certs.yml)
  - An unusually long-lived Teleport certificate was created
- [A SAML Connector was created or modified](../rules/gravitational_teleport_rules/teleport_saml_created.yml)
  - A SAML connector was created or modified
- [A Teleport Lock was created](../rules/gravitational_teleport_rules/teleport_lock_created.yml)
  - A Teleport Lock was created
- [A Teleport Role was modified or created](../rules/gravitational_teleport_rules/teleport_role_created.yml)
  - A Teleport Role was modified or created
- [A user authenticated with SAML, but from an unknown company domain](../rules/gravitational_teleport_rules/teleport_saml_login_not_company_domain.yml)
  - A user authenticated with SAML, but from an unknown company domain
- [A User from the company domain(s) Logged in without SAML](../rules/gravitational_teleport_rules/teleport_company_domain_login_without_saml.yml)
  - A User from the company domain(s) Logged in without SAML
- [Teleport Create User Accounts](../rules/gravitational_teleport_rules/teleport_create_user_accounts.yml)
  - A user has been manually created, modified, or deleted
- [Teleport Network Scan Initiated](../rules/gravitational_teleport_rules/teleport_network_scanning.yml)
  - A user has invoked a network scan that could potentially indicate enumeration of the network.
- [Teleport Scheduled Jobs](../rules/gravitational_teleport_rules/teleport_scheduled_jobs.yml)
  - A user has manually edited the Linux crontab
- [Teleport SSH Auth Errors](../rules/gravitational_teleport_rules/teleport_auth_errors.yml)
  - A high volume of SSH errors could indicate a brute-force attack
- [Teleport Suspicious Commands Executed](../rules/gravitational_teleport_rules/teleport_suspicious_commands.yml)
  - A user has invoked a suspicious command that could lead to a host compromise
- [User Logged in as root](../rules/gravitational_teleport_rules/teleport_root_login.yml)
  - A User logged in as root
- [User Logged in wihout MFA](../rules/gravitational_teleport_rules/teleport_local_user_login_without_mfa.yml)
  - A local User logged in without MFA


## ThinkstCanary

- [Thinkst Canary DCRC](../rules/thinkstcanary_rules/thinkst_canary_dcrc.yml)
  - A Canary has disconnected/reconnected.
- [Thinkst Canary Incident](../rules/thinkstcanary_rules/thinkst_canary_incident.yml)
  - A Canary incident has been detected.
- [Thinkst Canarytoken Incident](../rules/thinkstcanary_rules/thinkst_canarytoken_incident.yml)
  - A Canarytoken incident has been detected.


## Tines

- [Tines Actions Disabled Change](../rules/tines_rules/tines_actions_disabled_changes.yml)
  - Detections when Tines Actions are set to Disabled Change
- [Tines Custom CertificateAuthority setting changed](../rules/tines_rules/tines_custom_ca.yml)
  - Detects when Tines Custom CertificateAuthority settings are changed
- [Tines Enqueued/Retrying Job Deletion](../rules/tines_rules/tines_enqueued_retrying_job_deletion.yml)
  - Currently enqueued or retrying jobs were cleared
- [Tines Global Resource Destruction](../rules/tines_rules/tines_global_resource_destruction.yml)
  - A Tines user has destroyed a global resource.
- [Tines SSO Settings](../rules/tines_rules/tines_sso_settings.yml)
  - Detects when Tines SSO settings are changed
- [Tines Story Items Destruction](../rules/tines_rules/tines_story_items_destruction.yml)
  - A user has destroyed a story item
- [Tines Story Jobs Clearance](../rules/tines_rules/tines_story_jobs_clearance.yml)
  - A Tines User has cleared story jobs.
- [Tines Team Destruction](../rules/tines_rules/tines_team_destruction.yml)
  - A user has destroyed a team
- [Tines Tenant API Keys Added](../rules/tines_rules/tines_tenant_authtoken.yml)
  - Detects when Tines Tenant API Keys are added


## Tracebit

- [Tracebit Alert](../rules/tracebit_rules/tracebit_alert.yml)
  - Tracebit maintains security canaries across your organization to detect potential intrusions.This alert indicates that Tracebit has detected activity on security canaries.


# W

- [Wiz](#wiz)


## Wiz

- [Wiz Alert Passthrough Rule](../rules/wiz_rules/wiz_alert_passthrough.yml)
  - This rule enriches and contextualizes security alerts generated by Wiz.
- [Wiz CICD Scan Policy Updated Or Deleted](../rules/wiz_rules/wiz_cicd_scan_policy_updated_or_deleted.yml)
  - This rule detects updates and deletions of CICD scan policies.
- [Wiz Connector Updated Or Deleted](../rules/wiz_rules/wiz_connector_updated_or_deleted.yml)
  - This rule detects updates and deletions of connectors.
- [Wiz Data Classifier Updated Or Deleted](../rules/wiz_rules/wiz_data_classifier_updated_or_deleted.yml)
  - This rule detects updates and deletions of data classifiers.
- [Wiz Image Integrity Validator Updated Or Deleted](../rules/wiz_rules/wiz_image_integrity_validator_updated_or_deleted.yml)
  - This rule detects updates and deletions of image integrity validators.
- [Wiz Integration Updated Or Deleted](../rules/wiz_rules/wiz_integration_updated_or_deleted.yml)
  - This rule detects updates and deletions of Wiz integrations.
- [Wiz Issue Followed By SSH to EC2 Instance](../correlation_rules/wiz_issue_followed_by_ssh.yml)
  - Wiz detected a security issue with an EC2 instance followed by an SSH connection to the instance. This sequence could indicate a potential security breach.
- [Wiz Revoke User Sessions](../rules/wiz_rules/wiz_revoke_user_sessions.yml)
  - This rule detects user sessions revoked.
- [Wiz Rotate Service Account Secret](../rules/wiz_rules/wiz_rotate_service_account_secret.yml)
  - This rule detects service account secrets rotations.
- [Wiz Rule Change](../rules/wiz_rules/wiz_rule_change.yml)
  - This rule detects creations, updates and deletions of Wiz rules.
- [Wiz SAML Identity Provider Change](../rules/wiz_rules/wiz_saml_identity_provider_change.yml)
  - This rule detects creations, updates and deletions of SAML identity providers.
- [Wiz Service Account Change](../rules/wiz_rules/wiz_service_account_change.yml)
  - This rule detects creations, updates and deletions of service accounts.
- [Wiz Update IP Restrictions](../rules/wiz_rules/wiz_update_ip_restrictions.yml)
  - This rule detects updates of IP restrictions.
- [Wiz Update Login Settings](../rules/wiz_rules/wiz_update_login_settings.yml)
  - This rule detects updates of Wiz login settings.
- [Wiz Update Scanner Settings](../rules/wiz_rules/wiz_update_scanner_settings.yml)
  - This rule detects updates of Wiz scanner settings.
- [Wiz Update Support Contact List](../rules/wiz_rules/wiz_update_support_contact_list.yml)
  - This rule detects updates of Wiz support contact list.
- [Wiz User Created Or Deleted](../rules/wiz_rules/wiz_user_created_or_deleted.yml)
  - This rule detects creations and deletions of Wiz users.
- [Wiz User Role Updated Or Deleted](../rules/wiz_rules/wiz_user_role_updated_or_deleted.yml)
  - This rule detects updates and deletions of Wiz user roles.


# Z

- [Zeek](#zeek)
- [Zendesk](#zendesk)
- [Zoom](#zoom)
- [Zscaler](#zscaler)


## Zeek

- [Malicious SSO DNS Lookup](../rules/standard_rules/malicious_sso_dns_lookup.yml)
  - The rule looks for DNS requests to sites potentially posing as SSO domains.


## Zendesk

- [Admin Role Assigned](../rules/standard_rules/admin_assigned.yml)
  - Assigning an admin role manually could be a sign of privilege escalation
- [Enabled Zendesk Support to Assume Users](../rules/zendesk_rules/zendesk_user_assumption.yml)
  - User enabled or disabled zendesk support user assumption.
- [MFA Disabled](../rules/standard_rules/mfa_disabled.yml)
  - Detects when Multi-Factor Authentication (MFA) is disabled
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Zendesk Account Owner Changed](../rules/zendesk_rules/zendesk_new_owner.yml)
  - Only one admin user can be the account owner. Ensure the change in ownership is expected.
- [Zendesk API Token Created](../rules/zendesk_rules/zendesk_new_api_token.yml)
  - A user created a new API token to be used with Zendesk.
- [Zendesk Credit Card Redaction Off](../rules/zendesk_rules/zendesk_sensitive_data_redaction.yml)
  - A user updated account setting that disabled credit card redaction.
- [Zendesk Mobile App Access Modified](../rules/zendesk_rules/zendesk_mobile_app_access.yml)
  - A user updated account setting that enabled or disabled mobile app access.
- [Zendesk User Role Changed](../rules/zendesk_rules/zendesk_user_role.yml)
  - A user's Zendesk role was changed
- [Zendesk User Suspension Status Changed](../rules/zendesk_rules/zendesk_user_suspension.yml)
  - A user's Zendesk suspension status was changed.


## Zoom

- [New User Account Created](../rules/indicator_creation_rules/new_user_account_logging.yml)
  - A new account was created
- [Sign In from Rogue State](../rules/standard_rules/sign_in_from_rogue_state.yml)
  - Detects when an entity signs in from a nation associated with cyber attacks
- [Zoom All Meetings Secured With One Option Disabled](../rules/zoom_operation_rules/zoom_all_meetings_secured_with_one_option_disabled.yml)
  - A Zoom User turned off your organization's requirement that all meetings are secured with one security option.
- [Zoom Automatic Sign Out Disabled](../rules/zoom_operation_rules/zoom_automatic_sign_out_disabled.yml)
  - A Zoom User turned off your organization's setting to automatically sign users out after a specified period of time.
- [Zoom Meeting Passcode Disabled](../rules/zoom_operation_rules/zoom_operation_passcode_disabled.yml)
  - Meeting passcode requirement has been disabled from usergroup
- [Zoom New Meeting Passcode Required Disabled](../rules/zoom_operation_rules/zoom_new_meeting_passcode_required_disabled.yml)
  - A Zoom User turned off your organization's setting to require passcodes for new meetings.
- [Zoom Sign In Method Modified](../rules/zoom_operation_rules/zoom_sign_in_method_modified.yml)
  - A Zoom User modified your organizations sign in method.
- [Zoom Sign In Requirements Changed](../rules/zoom_operation_rules/zoom_sign_in_requirements_changed.yml)
  - A Zoom User changed your organization's sign in requirements.
- [Zoom Two Factor Authentication Disabled](../rules/zoom_operation_rules/zoom_two_factor_authentication_disabled.yml)
  - A Zoom User disabled your organization's setting to sign in with Two-Factor Authentication.
- [Zoom User Promoted to Privileged Role](../rules/zoom_operation_rules/zoom_user_promoted_to_privileged_role.yml)
  - A Zoom user was promoted to a privileged role.


## Zscaler

- [ZIA Account Access Removed](../rules/zscaler_rules/zia/zia_account_access_removal.yml)
  - This rule detects when admin user/role was deleted.
- [ZIA Additional Cloud Roles](../rules/zscaler_rules/zia/zia_additional_cloud_roles.yml)
  - This rule detects when an additional cloud role was created.
- [ZIA Backup Deleted](../rules/zscaler_rules/zia/zia_backup_deleted.yml)
  - This rule detects when ZIA backup data was deleted.
- [ZIA Cloud Account Created](../rules/zscaler_rules/zia/zia_create_cloud_account.yml)
  - This rule detects when new cloud account was created.
- [ZIA Golden Restore Point Dropped](../rules/zscaler_rules/zia/zia_golden_restore_point_dropped.yml)
  - This rule detects when ZIA goldenRestorePoint was dropped. It means that some piece of information that was impossible to delete before, now is deletable
- [ZIA Insecure Password Settings](../rules/zscaler_rules/zia/zia_insecure_password_settings.yml)
  - This rule detects when password settings are insecure.
- [ZIA Log Streaming Disabled](../rules/zscaler_rules/zia/zia_log_streaming_disabled.yml)
  - This rule detects when ZIA log streaming was disabled.
- [ZIA Logs Downloaded](../rules/zscaler_rules/zia/zia_logs_downloaded.yml)
  - This rule detects when ZIA Audit Logs were downloaded.
- [ZIA Password Expiration](../rules/zscaler_rules/zia/zia_password_expiration.yml)
  - This rule detects when password expiration eas set/removed.
- [ZIA Trust Modification](../rules/zscaler_rules/zia/zia_trust_modification.yml)
  - This rule detects when SAML authentication was enabled/disabled.


