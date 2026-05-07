from panther_anthropic_helpers import anthropic_actor_id, anthropic_alert_context


def rule(event):
    return event.get("type") == "mcp_server_deleted"


def title(event):
    actor_email = anthropic_actor_id(event)
    server_name = event.get("mcp_server_name", "<UNKNOWN_SERVER>")
    return f"Anthropic: MCP server [{server_name}] deleted by [{actor_email}]"


def dedup(event):
    return anthropic_actor_id(event)


def alert_context(event):
    return anthropic_alert_context(event)
