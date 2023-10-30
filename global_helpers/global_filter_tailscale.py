from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all Tailscale detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #  including event origin based actions:
    #    1. actions that originate from the admin console.
    #    2. events where events origin is undefined.
    #
    #
    # # example: event.origin
    # # if we don't know the event_origin, we want default behavior to be to alert on this event.
    # event_origin = deep_get(event, "event", "origin", default="")
    # return event_origin in ["ADMIN_CONSOLE", ""]
    #
    return True
