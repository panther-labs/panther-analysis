""" Global helpers for Snowflake streaming detections. """


def query_history_alert_context(event):
    return {
        "user": event.get("user_name", "<UNKNOWN USER>"),
        "role": event.get("role_name", "<UNKNOWN ROLE>"),
        "source": event.get("p_source_label", "<UNKNOWN SOURCE>"),
        # Not all queries are run in a warehouse; e.g.: getting worksheet files
        "warehouse": event.get("WAREHOUSE_NAME", "<NO WAREHOUSE>"),
    }
