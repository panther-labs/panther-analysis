from datetime import timedelta

from panther_detection_helpers.caching import put_dictionary

PREFIX = "Okta.LocationBehavior|"
TTL = timedelta(days=30).total_seconds()


def rule(event):
    key = PREFIX + event.get("id")
    put_dictionary(key, event.to_dict(), epoch_seconds=event.event_time_epoch() + TTL)
    return False
