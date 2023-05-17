from panther_base_helpers import deep_get  # pylint: disable=unused-import


def filter_include_event(event) -> bool:  # pylint: disable=unused-argument
    """
    filter_include_event provides a global include filter for all Auth0 detections
    Panther will not update this filter, and you can edit it without creating
    merge conflicts in the future.

    return True to include events, and False to exclude events
    """
    # This commented-out example would have the effect of
    #   ignoring all Auth0 organization logs except for
    #   the production Auth0 organization.
    # If you're ingesting Auth0 Enterprise Logs with multiple
    #   orgs, this may help to keep your detections running
    #   on the production orgs
    #
    #
    # # not all Auth0 enterprise events have org
    # # example: request domain
    # # if we don't know the request_domain, we want default behavior to be to alert on this event. 
    # request_domain = deep_get(event, "data", "details", "request", "channel", default="")
    # return request_domain in ["https://manage.auth0.com/", "https://mycompany.auth0.com", ""]
    #
    return True
