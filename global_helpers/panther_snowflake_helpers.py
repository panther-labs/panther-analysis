"""Global helpers for Snowflake streaming detections."""

from typing import Optional, Union

from panther_lookuptable_helpers import LookupTableMatches


class SnowflakeEnrichment(LookupTableMatches):
    """Helper to get Snowflake enrichment information for enriched fields"""

    def __init__(self, event):
        super().__init__()
        self.event = event
        self.source_label = event.get("p_source_label", "").lower().replace(" ", "_")

    def _get_enrichment_key(self, enrichment_type: str) -> str:
        """Generate enrichment key based on source label and enrichment type"""
        if not self.source_label:
            return ""
        return f"{self.source_label}_{enrichment_type}"

    def stages(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake stages enrichment data"""
        enrichment_key = self._get_enrichment_key("stages")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def grants_to_roles(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake grants to roles enrichment data"""
        enrichment_key = self._get_enrichment_key("grantsToRoles")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def grants_to_users(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake grants to users enrichment data"""
        enrichment_key = self._get_enrichment_key("grantsToUsers")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def network_policies(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake network policies enrichment data"""
        enrichment_key = self._get_enrichment_key("networkPolicies")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def roles(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake roles enrichment data"""
        enrichment_key = self._get_enrichment_key("roles")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def users(self, match_field: str = None) -> Union[dict, list, None]:
        """Get Snowflake users enrichment data"""
        enrichment_key = self._get_enrichment_key("users")
        if not enrichment_key:
            return None
        super()._register(self.event, enrichment_key)
        if match_field:
            return self._lookup(match_field)
        return self.lut_matches

    def get_user_info(self, user_name: str) -> Optional[dict]:
        """Get user information by user name"""
        users_data = self.users()
        if not users_data:
            return None

        for user_match in users_data.values():
            if isinstance(user_match, list):
                for user_info in user_match:
                    if user_info.get("NAME") == user_name:
                        return user_info
            elif isinstance(user_match, dict):
                if user_match.get("NAME") == user_name:
                    return user_match
        return None

    def get_role_info(self, role_name: str) -> Optional[dict]:
        """Get role information by role name"""
        roles_data = self.roles()
        if not roles_data:
            return None

        for role_match in roles_data.values():
            if isinstance(role_match, list):
                for role_info in role_match:
                    if role_info.get("NAME") == role_name:
                        return role_info
            elif isinstance(role_match, dict):
                if role_match.get("NAME") == role_name:
                    return role_match
        return None

    def get_user_roles(self, user_name: str) -> list:
        """Get all active roles granted to a specific user"""
        grants_data = self.grants_to_users()
        if not grants_data:
            return []

        user_roles = []
        for grant_match in grants_data.values():
            if isinstance(grant_match, list):
                for grant_info in grant_match:
                    if grant_info.get("GRANTEE_NAME") == user_name and not grant_info.get(
                        "DELETED_ON"
                    ):
                        user_roles.append(grant_info.get("ROLE"))
            elif isinstance(grant_match, dict):
                if grant_match.get("GRANTEE_NAME") == user_name and not grant_match.get(
                    "DELETED_ON"
                ):
                    user_roles.append(grant_match.get("ROLE"))
        return user_roles

    def get_role_privileges(self, role_name: str) -> list:
        """Get all active privileges granted to a specific role"""
        grants_data = self.grants_to_roles()
        if not grants_data:
            return []

        privileges = []
        for grant_match in grants_data.values():
            if isinstance(grant_match, list):
                for grant_info in grant_match:
                    if grant_info.get("GRANTEE_NAME") == role_name and not grant_info.get(
                        "DELETED_ON"
                    ):
                        privileges.append(
                            {
                                "privilege": grant_info.get("PRIVILEGE"),
                                "granted_on": grant_info.get("GRANTED_ON"),
                                "name": grant_info.get("NAME"),
                                "grant_option": grant_info.get("GRANT_OPTION"),
                            }
                        )
            elif isinstance(grant_match, dict):
                if grant_match.get("GRANTEE_NAME") == role_name and not grant_match.get(
                    "DELETED_ON"
                ):
                    privileges.append(
                        {
                            "privilege": grant_match.get("PRIVILEGE"),
                            "granted_on": grant_match.get("GRANTED_ON"),
                            "name": grant_match.get("NAME"),
                            "grant_option": grant_match.get("GRANT_OPTION"),
                        }
                    )
        return privileges

    def _is_admin_role_name(self, role_name: str) -> bool:
        """Check if role name indicates admin privileges"""
        admin_role_patterns = ["ACCOUNTADMIN", "SYSADMIN", "SECURITYADMIN", "USERADMIN", "ORGADMIN"]
        role_upper = role_name.upper()
        return any(admin_role in role_upper for admin_role in admin_role_patterns)

    def _has_admin_privileges(self, role_name: str) -> bool:
        """Check if role has admin-level privileges"""
        admin_privilege_indicators = [
            "CREATE ROLE",
            "DROP ROLE",
            "MANAGE GRANTS",
            "CREATE USER",
            "ALTER USER",
            "DROP USER",
            "CREATE ACCOUNT",
            "IMPORT SHARE",
            "CREATE SHARE",
            "APPLY MASKING POLICY",
            "APPLY ROW ACCESS POLICY",
            "CREATE MASKING POLICY",
            "CREATE ROW ACCESS POLICY",
        ]

        privileges = self.get_role_privileges(role_name)
        for priv in privileges:
            privilege_name = priv.get("privilege", "").upper()
            if privilege_name in admin_privilege_indicators:
                return True
            # Check for OWNERSHIP on sensitive objects
            if privilege_name == "OWNERSHIP":
                granted_on = priv.get("granted_on", "").upper()
                if granted_on in ["ACCOUNT", "ROLE", "USER"]:
                    return True
        return False

    def _get_user_roles_with_fallback(self, user_name: str) -> list:
        """Get user roles with fallback to event role if enrichment not available"""
        user_roles = self.get_user_roles(user_name)

        # If no enrichment data, fall back to checking role name from the event
        if not user_roles and hasattr(self, "event"):
            event_role = self.event.get("role_name")
            if event_role:
                user_roles = [event_role]

        return user_roles

    def is_admin(self, user_name: str = None, role_name: str = None) -> bool:
        """Check if a user or role has admin privileges

        Args:
            user_name: Username to check (will check all their roles)
            role_name: Specific role name to check

        Returns:
            bool: True if user/role has admin privileges
        """
        # Check specific role if provided
        if role_name:
            return self._is_admin_role_name(role_name) or self._has_admin_privileges(role_name)

        # Check user if provided
        if user_name:
            user_roles = self._get_user_roles_with_fallback(user_name)
            return any(
                self._is_admin_role_name(role) or self._has_admin_privileges(role)
                for role in user_roles
                if role
            )

        return False

    def get_admin_context(self, user_name: str = None) -> dict:
        """Get admin context information for a user

        Args:
            user_name: Username to check

        Returns:
            dict: Admin context with roles and privileges
        """
        if not user_name:
            return {"is_admin": False, "admin_roles": [], "admin_privileges": []}

        admin_roles = []
        admin_privileges = []
        user_roles = self.get_user_roles(user_name)

        # If no enrichment data, check event role
        if not user_roles and hasattr(self, "event"):
            event_role = self.event.get("role_name") or self.event.get("ROLE_NAME")
            if event_role:
                user_roles = [event_role]

        for role in user_roles:
            if not role:
                continue

            if self.is_admin(role_name=role):
                admin_roles.append(role)

                # Get specific active privileges for this admin role
                privileges = self.get_role_privileges(role)
                for priv in privileges:
                    admin_privileges.append(
                        {
                            "role": role,
                            "privilege": priv.get("privilege"),
                            "granted_on": priv.get("granted_on"),
                            "name": priv.get("name"),
                        }
                    )

        return {
            "is_admin": bool(admin_roles),
            "admin_roles": admin_roles,
            "admin_privileges": admin_privileges,
        }


def get_snowflake_enrichment(event) -> Optional[SnowflakeEnrichment]:
    """Returns a SnowflakeEnrichment object for the event or None if no enrichment is available"""
    if event.get("p_source_label") and event.deep_get("p_enrichment"):
        return SnowflakeEnrichment(event)
    return None


def query_history_alert_context(event):
    base_context = {
        "user": event.get("user_name", "<UNKNOWN USER>"),
        "role": event.get("role_name", "<UNKNOWN ROLE>"),
        "source": event.get("p_source_label", "<UNKNOWN SOURCE>"),
        # Not all queries are run in a warehouse; e.g.: getting worksheet files
        "warehouse": event.get("WAREHOUSE_NAME", "<NO WAREHOUSE>"),
    }

    enrichment = get_snowflake_enrichment(event)
    if enrichment:
        admin_context = enrichment.get_admin_context(event.get("user_name"))
        return base_context | admin_context

    return base_context
