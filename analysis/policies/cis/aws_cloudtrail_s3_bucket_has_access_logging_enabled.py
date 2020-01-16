def policy(resource):
    # TODO: Use the get_resource() helper func here
    return (
        resource['Bucket']['LoggingPolicy'] is not None or
        # Verify that the bucket exists in the same account
        resource['Bucket']['Location'] is None
    )
