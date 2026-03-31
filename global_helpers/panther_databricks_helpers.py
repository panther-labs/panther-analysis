"""Panther Databricks helper functions for Databricks.Audit log analysis."""

import re

# ============================================================================
# MAPPINGS & CONSTANTS
# ============================================================================

# Login action names mapped to authentication types
LOGIN_ACTIONS = {
    "aadBrowserLogin": "AAD Browser Login",
    "aadTokenLogin": "AAD Token Login",
    "certLogin": "Certificate Login",
    "jwtLogin": "JWT Login",
    "login": "Standard Login",
    "mfaLogin": "MFA Login",
    "oidcBrowserLogin": "OIDC Browser Login",
    "passwordVerifyAuthentication": "Password Authentication",
    "samlLogin": "SAML Login",
    "tokenLogin": "Token Login",
}

# Admin privilege modification actions
ADMIN_PRIVILEGE_ACTIONS = {
    "direct": ["setAdmin", "addAdmin", "removeAdmin", "setAccountAdmin", "changeAccountOwner"],
    "group": ["addPrincipalToGroup", "addPrincipalsToGroup", "removePrincipalFromGroup"],
}

# Configuration actions by category
CONFIG_ACTIONS = {
    "workspace": ["workspaceConfEdit", "updateWorkspaceSettings", "modifyWorkspaceConfiguration"],
    "account": ["updateAccountSettings", "modifyAccountConfiguration", "updateAccountMetastore"],
    "sso": ["create", "update", "delete"],
}

# IP access list configuration actions (not including IpAccessDenied, which is a login denial)
IP_ACCESS_ACTIONS = [
    "createIpAccessList",
    "updateIpAccessList",
    "deleteIpAccessList",
]

# Privilege modification actions (broad set for escalation detection)
PRIVILEGE_MODIFICATION_ACTIONS = [
    # Group membership
    "addPrincipalToGroup",
    "removePrincipalFromGroup",
    "addPrincipalsToGroup",
    # Admin privileges
    "setAdmin",
    "removeAdmin",
    "changeAccountOwner",
    "setAccountAdmin",
    # Role management
    "createRole",
    "deleteRole",
    "updateRole",
    "assignRole",
    "unassignRole",
    # Permissions and ownership
    "grant",
    "revoke",
    "updatePermissions",
    "setPermissions",
    "changeOwner",
    "createRoleAssignment",
    "deleteRoleAssignment",
    # Unity Catalog and workspace
    "updateMetastore",
    "updateWorkspaceAssignment",
    "updateCatalog",
    "updateSchema",
    "updateTable",
    "updateVolume",
    "updateFunction",
    "updateConnection",
]

# Unity Catalog temporary credential generation actions
TEMP_CREDENTIAL_ACTIONS = [
    "generateTemporaryTableCredential",
    "generateTemporaryVolumeCredential",
    "generateTemporaryPathCredential",
]

# Data download actions
DOWNLOAD_ACTIONS = [
    "downloadPreviewResults",
    "downloadLargeResults",
    "filesGet",
    "getModelVersionDownloadUri",
    "getModelVersionSignedDownloadUri",
    "workspaceExport",
    "downloadQueryResult",
]

# Group management actions
GROUP_ACTIONS = {
    "create": ["createGroup"],
    "delete": ["removeGroup", "deleteGroup"],
    "modify": ["updateGroup", "modifyGroup"],
    "membership": ["addPrincipalToGroup", "addPrincipalsToGroup", "removePrincipalFromGroup"],
}

# User management actions
USER_ACTIONS = {
    "create": ["createUser", "addUser"],
    "delete": ["delete", "deleteUser", "removeUser"],
    "modify": ["updateUser", "modifyUser"],
    "role": ["modifyUserRole", "addUserToAdminGroup"],
}

# Known system user identities (exclude from alerts)
SYSTEM_USERS = ["System-User"]

# Known Databricks service agents (exclude from alerts)
KNOWN_SERVICE_AGENTS = [
    "Databricks-Service/driver",
    "Databricks-Runtime",
    "Delta-Sharing-SparkStructuredStreaming",
    "RawDBHttpClient",
    "mlflow-python",
    "obsSDK-scala",
    "wsfs",
    "feature-store",
]

# MFA management actions
MFA_ACTIONS = {
    "add": ["mfaAddKey"],
    "delete": ["mfaDeleteKey"],
}

# Data movement actions involving explicit credentials
DATA_MOVEMENT_CREDENTIAL_ACTIONS = [
    "mount",
    "createStorageCredential",
    "updateStorageCredential",
    "createConnection",
    "updateConnection",
]

# Excluded paths (system/telemetry operations)
EXCLUDED_PATHS = ["telemetry", "delta-commit", "health", "metrics", "status"]


def databricks_alert_context(event, additional_fields=None):
    """
    Generate standardized alert context for Databricks audit events.

    Args:
        event: The Databricks audit event dictionary
        additional_fields: Optional dict of additional key-value pairs to include

    Returns:
        Dictionary containing common context fields plus any additional fields
    """
    context = {
        "actor": event.deep_get("userIdentity", "email"),
        "service_name": event.get("serviceName"),
        "action": event.get("actionName"),
        "source_ip": event.get("sourceIPAddress"),
        "user_agent": event.get("userAgent"),
        "audit_level": event.get("auditLevel"),
        "workspace_id": event.get("workspaceId"),
        "account_id": event.get("accountId"),
        "status_code": event.deep_get("response", "statusCode"),
        "error_message": event.deep_get("response", "errorMessage"),
        "request_id": event.get("requestId"),
    }

    # Add additional fields if provided
    if additional_fields and isinstance(additional_fields, dict):
        context.update(additional_fields)

    # Remove None values to keep context clean
    return {k: v for k, v in context.items() if v is not None}


def is_databricks_employee_auth(event):
    """
    Check if the event represents Databricks employee authentication.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is employee authentication
    """
    auth_method = event.deep_get("requestParams", "authentication_method")
    return auth_method == "GENIE_AUTH"


def get_principal_type(principal_identifier):
    """
    Determine the type of principal based on the identifier format.

    Args:
        principal_identifier: String identifier (email, UUID, or group name)

    Returns:
        String: "User", "Service Principal", "Group", or "Unknown"
    """
    if not principal_identifier:
        return "Unknown"

    # Check for email pattern
    if re.match(r".+@.+\.[a-zA-Z]{2,}", principal_identifier):
        return "User"

    # Check for UUID pattern (service principal)
    uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    if re.match(uuid_pattern, principal_identifier):
        return "Service Principal"

    # Otherwise assume it's a group name
    return "Group"


def is_admin_group(group_name):
    """
    Check if a group name indicates administrative privileges.

    Args:
        group_name: String name of the group

    Returns:
        Boolean indicating if this is likely an admin group
    """
    if not group_name:
        return False

    admin_indicators = ["admin", "administrator", "owner", "root", "superuser"]
    group_lower = group_name.lower()
    return any(indicator in group_lower for indicator in admin_indicators)


def extract_target_principal(event):
    """
    Extract the target principal from various possible locations in request params.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        String identifier of the target principal, or None if not found
    """
    # Check various common field names for target principal
    target_fields = [
        ("requestParams", "targetUserName"),
        ("requestParams", "target_user_name"),
        ("requestParams", "principal"),
        ("requestParams", "targetServicePrincipalName"),
        ("requestParams", "targetGroupId"),
        ("requestParams", "targetGroupName"),
    ]

    for path in target_fields:
        value = event.deep_get(*path)
        if value:
            return value

    return None


def extract_group_identifier(event):
    """
    Extract group identifier from various possible field locations.
    Handles different field names and endpoint-specific locations.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        String identifier of the group, or None if not found
    """
    # Check endpoint type first
    endpoint = event.deep_get("requestParams", "endpoint")

    # For permission/role assignments, group might be in targetUserName
    if endpoint in ["permissionAssignment", "roleAssignment"]:
        return event.deep_get("requestParams", "targetUserName")

    # Check standard group field locations
    group_fields = [
        ("requestParams", "targetGroupName"),
        ("requestParams", "groupName"),
        ("requestParams", "targetGroupId"),
        ("requestParams", "groupId"),
        ("requestParams", "group"),
    ]

    for path in group_fields:
        value = event.deep_get(*path)
        if value:
            return value

    return None


def is_login_action(event):
    """
    Check if the event represents a login action.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is a login action
    """
    action_name = event.get("actionName")
    return action_name in LOGIN_ACTIONS


def is_admin_privilege_action(event):
    """
    Check if the event represents an admin privilege modification.
    Handles both direct privilege grants and group-based privilege changes.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is an admin privilege action
    """
    action_name = event.get("actionName")

    # Check direct admin actions
    if action_name in ADMIN_PRIVILEGE_ACTIONS["direct"]:
        return True

    # Check group-based admin actions
    if action_name in ADMIN_PRIVILEGE_ACTIONS["group"]:
        group_name = extract_group_identifier(event)
        if group_name and is_admin_group(group_name):
            return True

    return False


def is_group_management_action(event, action_category=None):
    """
    Check if the event represents a group management action.

    Args:
        event: The Databricks audit event dictionary
        action_category: Optional specific category to check (create/delete/modify/membership)

    Returns:
        Boolean indicating if this is a group management action
    """
    action_name = event.get("actionName")

    if action_category:
        return action_name in GROUP_ACTIONS.get(action_category, [])

    # Check all categories
    for actions in GROUP_ACTIONS.values():
        if action_name in actions:
            return True
    return False


def is_service_agent(event):
    """
    Check if the event originated from a known Databricks service agent.
    Useful for filtering out automated system operations.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is a service agent
    """
    user_agent = event.get("userAgent", "")
    return any(agent in user_agent for agent in KNOWN_SERVICE_AGENTS)


def is_excluded_path(event):
    """
    Check if the request path should be excluded (telemetry, health checks, etc).

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this path should be excluded
    """
    path = event.deep_get("requestParams", "path", default="")
    return any(excluded in path for excluded in EXCLUDED_PATHS)


def is_config_change(event, config_category=None):
    """
    Check if the event represents a configuration change.

    Args:
        event: The Databricks audit event dictionary
        config_category: Optional specific category to check (workspace/account/sso)

    Returns:
        Boolean indicating if this is a configuration change
    """
    action_name = event.get("actionName")
    service_name = event.get("serviceName")

    if config_category:
        # Match category-specific patterns
        if config_category == "workspace" and service_name == "workspace":
            return action_name in CONFIG_ACTIONS["workspace"]
        if config_category == "account" and service_name == "accounts":
            return action_name in CONFIG_ACTIONS["account"]
        if config_category == "sso" and service_name == "ssoConfigBackend":
            return action_name in CONFIG_ACTIONS["sso"]
        return False

    # Check any config change, with service name guard to prevent
    # generic SSO actions ("create", "update", "delete") from matching non-config events
    service_action_map = {
        "workspace": CONFIG_ACTIONS["workspace"],
        "accounts": CONFIG_ACTIONS["account"],
        "ssoConfigBackend": CONFIG_ACTIONS["sso"],
    }
    return action_name in service_action_map.get(service_name, [])


def get_config_key_value(event):
    """
    Extract configuration key and value from workspace configuration changes.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Tuple of (config_key, config_value) or (None, None) if not found
    """
    config_key = event.deep_get("requestParams", "workspaceConfKeys")
    config_value = event.deep_get("requestParams", "workspaceConfValues")
    return config_key, config_value


def is_critical_config_change(event):
    """
    Check if the configuration change is security-critical.
    Critical changes include: audit logging, IP access lists, MFA settings.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is a critical configuration change
    """
    config_key, _ = get_config_key_value(event)

    # Critical configuration keys
    critical_configs = [
        "enableVerboseAuditLogs",
        "enforceMFA",
        "requireWorkspaceApproval",
        "customerApprovedWSLoginExpirationTime",
    ]

    if config_key in critical_configs:
        return True

    # IP access list changes are always critical
    action_name = event.get("actionName")
    if action_name in IP_ACCESS_ACTIONS:
        return True

    return False


# ============================================================================
# COMPOSITE FILTERS (Common rule patterns)
# ============================================================================


def filter_noise(event):
    """
    Filter out common noise/false positives: service agents, telemetry, health checks, tokens.
    Use this as a quick pre-filter in rules to reduce alert fatigue.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean: True if event should be FILTERED OUT (is noise), False if event is legitimate
    """
    # Filter service agents
    if is_service_agent(event):
        return True

    # Filter excluded paths
    if is_excluded_path(event):
        return True

    # Filter service principal identities (UUIDs as usernames).
    # NOTE: This suppresses all service principal activity. If monitoring compromised
    # service principals is required, remove this filter or use a targeted allowlist.
    user_email = event.deep_get("userIdentity", "email", default="")
    uuid_pattern = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    if re.match(uuid_pattern, user_email):
        return True

    return False


def should_alert_on_group_change(event, change_type="delete"):
    """
    Determine if a group change should generate an alert.
    Filters out noise and checks for successful actions.

    Args:
        event: The Databricks audit event dictionary
        change_type: Type of change to check for (delete/modify/membership)

    Returns:
        Boolean indicating if an alert should be generated
    """
    # Filter noise
    if filter_noise(event):
        return False

    # Check if it's the right type of group action
    if not is_group_management_action(event, action_category=change_type):
        return False

    # Must be on accounts service for group management
    if event.get("serviceName") != "accounts":
        return False

    return True


def is_metastore_admin_action(event):
    """
    Check if the event represents metastore admin privilege changes.
    Includes metastore ownership changes and metastore admin group membership.

    Args:
        event: The Databricks audit event dictionary

    Returns:
        Boolean indicating if this is a metastore admin action
    """
    action_name = event.get("actionName")

    # Direct metastore ownership change
    if action_name == "updateMetastore":
        return "owner" in event.get("requestParams", {})

    # Metastore admin group membership
    if is_admin_privilege_action(event):
        group = extract_group_identifier(event)
        if not group:
            return False

        metastore_keywords = ["metastore", "unity", "catalog"]
        group_lower = group.lower()
        return any(keyword in group_lower for keyword in metastore_keywords)

    return False
