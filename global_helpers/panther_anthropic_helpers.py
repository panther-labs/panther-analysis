from panther_base_helpers import pantherflow_investigation


def anthropic_alert_context(event):
    """Returns common context for Anthropic Activity alerts"""
    context = {
        "event_type": event.get("type", ""),
        "actor_type": event.deep_get("actor", "type", default=""),
        "actor_email": event.deep_get("actor", "email_address", default=""),
        "actor_user_id": event.deep_get("actor", "user_id", default=""),
        "ip_address": event.deep_get("actor", "ip_address", default=""),
        "user_agent": event.deep_get("actor", "user_agent", default=""),
        "api_key_id": event.deep_get("actor", "api_key_id", default=""),
        "organization_id": event.get("organization_id", ""),
        "ips": event.get("p_any_ip_addresses", []),
        "PantherFlow Investigation": pantherflow_investigation(event),
    }
    optional_context = {
        "target_id": event.get("target_id"),
        "target_type": event.get("target_type"),
        "role": event.get("role"),
        "resource_type": event.get("resource_type"),
        "resource_id": event.get("resource_id"),
        "updates": event.get("updates"),
        "claude_chat_id": event.get("claude_chat_id"),
        "claude_project_id": event.get("claude_project_id"),
        "mcp_server_id": event.get("mcp_server_id"),
        "mcp_server_name": event.get("mcp_server_name"),
        "integration_type": event.get("integration_type"),
        "audience": event.get("audience"),
        "is_enabled": event.get("is_enabled"),
        "admin_api_key_id": event.get("admin_api_key_id"),
        "service_key_id": event.get("service_key_id"),
        "service_name": event.get("service_name"),
        "connection_id": event.get("connection_id"),
        "deleted_user_id": event.get("deleted_user_id"),
        "deleted_user_email": event.get("deleted_user_email"),
    }
    context.update({k: v for k, v in optional_context.items() if v})
    return context
