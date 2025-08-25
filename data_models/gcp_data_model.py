import json
from fnmatch import fnmatch

import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get
from panther_gcp_helpers import get_binding_deltas

ADMIN_ROLES = {
    # Primitive Rolesx
    "roles/owner",
    # Predefined Roles
    "roles/*Admin",
}


def get_event_type(event):
    # pylint: disable=too-many-return-statements, too-many-branches, too-complex
    service_name = deep_get(event, "protoPayload", "serviceName", default="")
    method_name = deep_get(event, "protoPayload", "methodName", default="")

    # Authentication Events (Google Workspace Login)
    if service_name == "login.googleapis.com":
        if method_name == "google.login.LoginService.loginSuccess":
            return event_type.SUCCESSFUL_LOGIN
        if method_name == "google.login.LoginService.loginFailure":
            return event_type.FAILED_LOGIN
        if method_name in [
            "google.login.LoginService.2svEnroll",
            "google.login.LoginService.loginVerification",
        ]:
            # Check if MFA was used
            is_second_factor = deep_get(
                event, "protoPayload", "request", "is_second_factor", default=False
            )
            if is_second_factor or "2sv" in method_name:
                return event_type.MFA_ENABLED
        if method_name == "google.login.LoginService.2svDisable":
            return event_type.MFA_DISABLED
        if method_name == "google.login.LoginService.suspiciousLogin":
            return event_type.FAILED_LOGIN

    # IAM and Service Account Events
    if service_name == "iam.googleapis.com":
        if method_name in [
            "google.iam.admin.v1.CreateServiceAccount",
            "google.iam.v1.CreateServiceAccount",
        ]:
            return event_type.USER_ACCOUNT_CREATED
        if method_name in [
            "google.iam.admin.v1.DeleteServiceAccount",
            "google.iam.v1.DeleteServiceAccount",
        ]:
            return event_type.USER_ACCOUNT_DELETED
        if method_name in [
            "google.iam.admin.v1.CreateServiceAccountKey",
            "google.iam.admin.v1.DeleteServiceAccountKey",
            "google.iam.admin.v1.UpdateServiceAccount",
            "google.iam.admin.v1.EnableServiceAccount",
            "google.iam.admin.v1.DisableServiceAccount",
        ]:
            return event_type.USER_ACCOUNT_MODIFIED
        # IAM Role Management
        if method_name in ["google.iam.admin.v1.CreateRole", "google.iam.admin.v1.DeleteRole"]:
            if "Create" in method_name:
                return event_type.USER_ROLE_CREATED
            return event_type.USER_ROLE_DELETED

    # Google Workspace Admin (User Lifecycle)
    if service_name == "admin.googleapis.com":
        if "CreateUser" in method_name or "InsertUser" in method_name:
            return event_type.USER_ACCOUNT_CREATED
        if "DeleteUser" in method_name:
            return event_type.USER_ACCOUNT_DELETED
        if method_name in [
            "google.admin.AdminService.changeUserPassword",
            "google.admin.AdminService.updateUser",
        ]:
            return event_type.USER_ACCOUNT_MODIFIED
        if "CreateGroup" in method_name or "InsertGroup" in method_name:
            return event_type.USER_GROUP_CREATED
        if "DeleteGroup" in method_name:
            return event_type.USER_GROUP_DELETED

    # Cloud Resource Manager (Organization/Project Events)
    if service_name == "cloudresourcemanager.googleapis.com":
        if method_name in [
            "google.cloud.resourcemanager.v1.Projects.CreateProject",
            "google.cloud.resourcemanager.v3.Projects.CreateProject",
        ]:
            return event_type.ACCOUNT_CREATED
        if method_name in [
            "google.cloud.resourcemanager.v1.Projects.DeleteProject",
            "google.cloud.resourcemanager.v3.Projects.DeleteProject",
        ]:
            return event_type.ACCOUNT_DELETED

    # Security Configuration Changes
    # VPC and Firewall
    if service_name == "compute.googleapis.com":
        if method_name in [
            "compute.firewalls.insert",
            "compute.firewalls.delete",
            "compute.firewalls.patch",
            "compute.networks.insert",
            "compute.networks.delete",
            "compute.subnetworks.insert",
            "compute.subnetworks.delete",
        ]:
            return event_type.SECURITY_CONFIG_CHANGED

    # Cloud KMS (Key Management)
    if service_name == "cloudkms.googleapis.com":
        if method_name in [
            "google.cloud.kms.v1.KeyManagementService.CreateCryptoKey",
            "google.cloud.kms.v1.KeyManagementService.DestroyCryptoKeyVersion",
            "google.cloud.kms.v1.KeyManagementService.UpdateCryptoKey",
        ]:
            return event_type.SECURITY_CONFIG_CHANGED

    # Cloud Storage (Bucket Policies and ACLs)
    if service_name == "storage.googleapis.com":
        if method_name in [
            "storage.buckets.setIamPolicy",
            "storage.buckets.update",
            "storage.objects.setIamPolicy",
            "storage.bucketAccessControls.insert",
            "storage.bucketAccessControls.delete",
        ]:
            return event_type.SECURITY_CONFIG_CHANGED

    # Security Command Center
    if service_name == "securitycenter.googleapis.com":
        if method_name in [
            "google.cloud.securitycenter.v1.SecurityCenter.UpdateOrganizationSettings",
            "google.cloud.securitycenter.v1.SecurityCenter.UpdateSource",
        ]:
            return event_type.SECURITY_CONFIG_CHANGED

    # IAM Policy Changes (existing logic enhanced)
    for delta in get_binding_deltas(event):
        if delta["action"] == "ADD":
            if any(
                (
                    fnmatch(delta.get("role", ""), admin_role_pattern)
                    for admin_role_pattern in ADMIN_ROLES
                )
            ):
                return event_type.ADMIN_ROLE_ASSIGNED
            # Regular permission grants
            return event_type.PERMISSION_GRANTED
        if delta["action"] == "REMOVE":
            return event_type.PERMISSION_REVOKED

    return None


def get_admin_map(event):
    roles_assigned = {}
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD":
            roles_assigned[delta.get("member")] = delta.get("role")

    return roles_assigned


def get_modified_users(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.keys()))


def get_iam_roles(event):
    event_dict = event.to_dict()
    roles_assigned = get_admin_map(event_dict)

    return json.dumps(list(roles_assigned.values()))


def get_api_group(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[0]
    except IndexError:
        return ""


def get_api_version(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[1]
    except IndexError:
        return ""


def get_namespace(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[3]
    except IndexError:
        return ""


def get_resource(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[4]
    except IndexError:
        return ""


def get_name(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    try:
        return deep_get(event, "protoPayload", "resourceName", default="").split("/")[5]
    except IndexError:
        return ""


def get_request_uri(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    return "/apis/" + deep_get(event, "protoPayload", "resourceName", default="")


def get_source_ips(event):
    caller_ip = deep_get(event, "protoPayload", "requestMetadata", "callerIP", default=None)
    if caller_ip:
        return [caller_ip]
    return []


def get_verb(event):
    if deep_get(event, "protoPayload", "serviceName", default="") != "k8s.io":
        return ""
    return deep_get(event, "protoPayload", "methodName", default="").split(".")[-1]


def get_actor_user(event):
    authentication_info = deep_get(event, "protoPayload", "authenticationInfo", default={})
    if principal_email := authentication_info.get("principalEmail"):
        return principal_email
    return authentication_info.get("principalSubject", "<UNKNOWN ACTOR USER>")
