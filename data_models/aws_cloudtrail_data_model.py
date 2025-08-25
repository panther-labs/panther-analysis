import ipaddress

import panther_event_type_helpers as event_type
from panther_aws_helpers import get_actor_user  # pylint: disable=unused-import
from panther_base_helpers import deep_get


def get_event_type(event):
    # pylint: disable=too-many-return-statements, too-many-branches, too-complex

    event_name = event.get("eventName", "")
    error_code = event.get("errorCode")

    # Handle failed API calls (unauthorized access attempts)
    if error_code in [
        "AccessDenied",
        "UnauthorizedOperation",
        "InvalidUserID.NotFound",
        "SigninFailure",
        "TokenRefreshRequired",
    ]:
        if "Login" in event_name or "Signin" in event_name:
            return event_type.FAILED_LOGIN
        return None  # Failed API calls handled by detection rules, not data model

    # Authentication Events (handle all user identity types)
    if event_name == "ConsoleLogin":
        if deep_get(event, "responseElements", "ConsoleLogin") == "Failure":
            return event_type.FAILED_LOGIN
        if deep_get(event, "responseElements", "ConsoleLogin") == "Success":
            return event_type.SUCCESSFUL_LOGIN

    # Handle federated and assumed role authentication
    if event_name in ["AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"]:
        if error_code:
            return event_type.FAILED_LOGIN
        return event_type.SUCCESSFUL_LOGIN

    # User/Role Lifecycle Events
    if event_name == "CreateUser":
        return event_type.USER_ACCOUNT_CREATED
    if event_name == "DeleteUser":
        return event_type.USER_ACCOUNT_DELETED
    if event_name in ["ChangePassword", "CreateAccessKey", "CreateLoginProfile"]:
        return event_type.USER_ACCOUNT_MODIFIED
    if event_name == "CreateAccountResult":
        return event_type.ACCOUNT_CREATED

    # Organization Security Events
    if event_name in ["CreateAccount", "InviteAccountToOrganization", "AcceptHandshake"]:
        return event_type.ACCOUNT_CREATED
    if event_name in ["LeaveOrganization", "RemoveAccountFromOrganization", "CloseAccount"]:
        return event_type.ACCOUNT_DELETED

    # Role Events
    if event_name == "CreateRole":
        return event_type.USER_ROLE_CREATED
    if event_name == "DeleteRole":
        return event_type.USER_ROLE_DELETED
    if event_name == "AssumeRole":
        return event_type.PERMISSION_GRANTED
    if event_name == "SwitchRole":
        return event_type.PERMISSION_GRANTED

    # MFA Events (comprehensive coverage)
    if event_name in ["EnableMFADevice", "CreateVirtualMFADevice", "ResyncMFADevice"]:
        return event_type.MFA_ENABLED
    if event_name in ["DeactivateMFADevice", "DeleteVirtualMFADevice"]:
        return event_type.MFA_DISABLED
    # MFA-protected API calls
    if event_name == "GetSessionToken" and deep_get(event, "requestParameters", "SerialNumber"):
        return event_type.MFA_ENABLED

    # Permission Changes (including advanced IAM controls)
    if event_name in [
        "AttachUserPolicy",
        "PutUserPolicy",
        "AttachRolePolicy",
        "PutRolePolicy",
        "AttachGroupPolicy",
        "PutGroupPolicy",
        "UpdateAssumeRolePolicy",
        "PutUserPermissionsBoundary",
        "CreateSAMLProvider",
    ]:
        return event_type.PERMISSION_GRANTED
    if event_name in [
        "DetachUserPolicy",
        "DetachRolePolicy",
        "DetachGroupPolicy",
        "DeleteUserPermissionsBoundary",
        "DeleteSAMLProvider",
    ]:
        return event_type.PERMISSION_REVOKED

    # Group Management
    if event_name == "CreateGroup":
        return event_type.USER_GROUP_CREATED
    if event_name == "DeleteGroup":
        return event_type.USER_GROUP_DELETED
    if event_name == "AddUserToGroup":
        return event_type.PERMISSION_GRANTED
    if event_name == "RemoveUserFromGroup":
        return event_type.PERMISSION_REVOKED

    # Security Configuration Changes
    if event_name in [
        # Encryption/Security Controls
        "DisableEbsEncryptionByDefault",
        "EnableEbsEncryptionByDefault",
        # KMS Key Operations
        "CreateKey",
        "DeleteKey",
        "ScheduleKeyDeletion",
        "CancelKeyDeletion",
        "DisableKey",
        "EnableKey",
        "PutKeyPolicy",
        "CreateAlias",
        "DeleteAlias",
        # CloudTrail/Config/GuardDuty/Security Hub
        "StopConfigurationRecorder",
        "DeleteDeliveryChannel",
        "CreateTrail",
        "DeleteTrail",
        "StopLogging",
        "PutEventSelectors",
        "DisableGuardDuty",
        "StopMonitoringMembers",
        "DisassociateFromMasterAccount",
        "UpdateDetector",
        "CreateThreatIntelSet",
        "DeleteThreatIntelSet",
        "BatchDisableStandards",
        "UpdateStandardsControl",
        "DisableSecurityHub",
        # AWS Config Events
        "PutConfigRule",
        "DeleteConfigRule",
        "PutConfigurationRecorder",
        "DeleteConfigurationRecorder",
        "PutDeliveryChannel",
        "StopConfigurationRecorder",
        # CloudWatch Events
        "PutMetricAlarm",
        "DeleteAlarms",
        "DisableAlarmActions",
        "EnableAlarmActions",
        "CreateLogGroup",
        "DeleteLogGroup",
        "PutLogEvents",
        "CreateLogStream",
        # S3 Security Events (bucket policy and public access)
        "PutBucketAcl",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "PutBucketVersioning",
        "PutBucketLogging",
        "PutBucketNotification",
        # VPC/Network Security
        "CreateVpc",
        "DeleteVpc",
        "CreateRoute",
        "DeleteRoute",
        "ReplaceRoute",
        "CreateNetworkAcl",
        "DeleteNetworkAcl",
        "ReplaceNetworkAclEntry",
        "CreateInternetGateway",
        "DeleteInternetGateway",
        "AttachInternetGateway",
        "DetachInternetGateway",
        "CreateVpnGateway",
        "DeleteVpnGateway",
        "CreateNatGateway",
        "DeleteNatGateway",
        "CreateRouteTable",
        "DeleteRouteTable",
        # EC2/Lambda Security Events
        "ModifyInstanceAttribute",
        "StopInstances",
        "TerminateInstances",
        "CreateImage",
        "ModifyImageAttribute",
        "CreateSnapshot",
        "ModifySnapshotAttribute",
        "CreateFunction",
        "UpdateFunctionConfiguration",
        "UpdateFunctionCode",
        "AddPermission",
        "RemovePermission",
        "PutFunctionConcurrency",
        "DeleteFunction",
        # Certificate Management
        "RequestCertificate",
        "DeleteCertificate",
        "ImportCertificate",
        # Systems Manager
        "PutParameter",
        "DeleteParameter",
        "PutParameterStorePolicy",
        # Security Groups/NACLs
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
    ]:
        return event_type.SECURITY_CONFIG_CHANGED

    return None


def load_ip_address(event):
    """
    CloudTrail occasionally sets non-IPs in the sourceIPAddress field.
    This method ensures that either an IPv4 or IPv6 address is always returned.
    """
    source_ip = event.get("sourceIPAddress")
    if not source_ip:
        return None
    try:
        ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(source_ip)
        except ipaddress.AddressValueError:
            return None
    return source_ip
