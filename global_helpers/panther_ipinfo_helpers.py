from panther_base_helpers import deep_get


class PantherIPInfoException(Exception):
    def __init__(self):
        message = "Please enable both IPInfo Location and ASN Lookup Tables"
        super().__init__(message)

class PantherIPInfoNoneException(Exception):
    def __init__(self, message):
        super().__init__(message)

class IPInfoLocation:
    def __init__(self, event):
        self.ipinfo_location = deep_get(event, "p_enrichment", "ipinfo_location_detections_engine")
        self.event = event

    def city(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "city")

    def country(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "country")

    def latitude(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "lat")

    def longitude(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "lng")

    def postal_code(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "postal_code")

    def region(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "region")

    def region_code(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "region_code")

    def timezone(self, match_field) -> str:
        return deep_get(self.ipinfo_location, match_field, "timezone")

    def ip_address(self, match_field):
        if isinstance(deep_get(self.event, match_field), (list, str)):
            return deep_get(self.event, match_field)
        elif isinstance(deep_get(self.event, match_field), dict):
            return deep_get(self.event, match_field, "ip")
        elif deep_get(self.event, match_field) is None:
            raise PantherIPInfoNoneException(f"{match_field} is returns None")


class IPInfoASN:
    def __init__(self, event):
        self.ipinfo_asn = deep_get(event, "p_enrichment", "ipinfo_asn_detections_engine")
        self.event = event

    def asn(self, match_field) -> str:
        return deep_get(self.ipinfo_asn, match_field, "asn")

    def domain(self, match_field) -> str:
        return deep_get(self.ipinfo_asn, match_field, "domain")

    def name(self, match_field) -> str:
        return deep_get(self.ipinfo_asn, match_field, "name")

    def route(self, match_field) -> str:
        return deep_get(self.ipinfo_asn, match_field, "route")

    def asn_type(self, match_field) -> str:
        return deep_get(self.ipinfo_asn, match_field, "type")

    def ip_address(self, match_field):
        if isinstance(deep_get(self.event, match_field), (list, str)):
            return deep_get(self.event, match_field)
        elif isinstance(deep_get(self.event, match_field), dict):
            return deep_get(self.event, match_field, "ip")
        elif deep_get(self.event, match_field) is None:
            raise PantherIPInfoNoneException(f"{match_field} is returns None")


def get_ipinfo_location_object(event):
    if deep_get(event, "p_enrichment", "ipinfo_location_detections_engine"):
        return IPInfoLocation(event)
    return None


def get_ipinfo_asn_object(event):
    if deep_get(event, "p_enrichment", "ipinfo_asn_detections_engine"):
        return IPInfoASN(event)
    return None


def geoinfo_from_ip(event, match_field):
    location = get_ipinfo_location_object(event)
    asn = get_ipinfo_asn_object(event)
    if location and asn:
        return {
            "ip": event.get(match_field),
            # "hostname": "",
            # TODO: Couldn't find this field in Location or ASN
            # "anycast": true,
            # TODO: This field was listed in the example output, but not present in any requests
            "city": location.city(match_field),
            "region": location.region(match_field),
            "country": location.country(match_field),
            "loc": f"{location.latitude(match_field)},{location.longitude(match_field)}",
            "org": f"{asn.asn(match_field)} {asn.name(match_field)}",
            "postal": location.postal_code(match_field),
            "timezone": location.timezone(match_field),
        }
    raise PantherIPInfoException
