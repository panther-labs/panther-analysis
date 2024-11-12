from panther_zscaler_helpers import zia_alert_context, zia_success


def rule(event):
    if not zia_success(event):
        return False
    action = event.deep_get("event", "action", default="ACTION_NOT_FOUND")
    category = event.deep_get("event", "category", default="CATEGORY_NOT_FOUND")
    golden_restore_point_pre = event.deep_get(
        "event",
        "preaction",
        "goldenRestorePoint",
        default="<PRE_RESTORE_POINT_NOT_FOUND>",
    )
    golden_restore_point_post = event.deep_get(
        "event",
        "postaction",
        "goldenRestorePoint",
        default="<POPT_RESTORE_POINT_NOT_FOUND>",
    )
    if (
        action == "UPDATE"
        and category == "BACKUP_AND_RESTORE"
        and golden_restore_point_pre is True
        and golden_restore_point_post is False
    ):
        return True
    return False


def title(event):
    return (
        f"[Zscaler.ZIA]: goldenRestorePoint was dropped by admin with id "
        f"[{event.deep_get('event', 'adminid', default='<ADMIN_ID_NOT_FOUND>')}]"
    )


def alert_context(event):
    return zia_alert_context(event)
