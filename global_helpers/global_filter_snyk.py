from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all snyk detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    # including only:
    #    1. the specific orgId mentioned.
    #    2. events where orgId is undefined
    #
    # # not all snyk audit events have orgId & projectId
    # # example: group.user.add, sometimes api.access
    # org = deep_get(event, "orgId", default="")
    # return org in ["21111111-a222-4eee-8ddd-a99999999999", ""]
    #
    return True
