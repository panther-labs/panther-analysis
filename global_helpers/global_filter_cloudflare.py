from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all cloudflare detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #   "only include events if ClientRequestHost contains www.example.com"
    # if "www.example.com" in event.get("ClientRequestHost", ""):
    #     return True
    # return False
    #
    return True
