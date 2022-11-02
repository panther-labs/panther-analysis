#!/usr/bin/env python
# Unit tests for functions inside global_helpers

import datetime
import os
import sys
import unittest

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))

import panther_base_helpers as p_b_h  # pylint: disable=C0413
import panther_tor_helpers as p_tor_h  # pylint: disable=C0413
import panther_ipinfo_helpers as p_i_h  # pylint: disable=C0413


class TestGetValFromList(unittest.TestCase):
    def setUp(self):
        self.input = [
            {"actor": 1, "one": 1, "select": "me"},
            {"actor": 2, "two": 2, "select": "me"},
            {"actor": 3, "three": 3, "select": "not_me"},
        ]

    def test_input_key_exists(self):
        response = p_b_h.get_val_from_list(self.input, "actor", "select", "me")
        should_be = set()
        should_be.add(1)
        should_be.add(2)
        self.assertCountEqual(response, should_be)

    # This test case validate that get_val_from_list will return the
    # empty set when the comparison key is not found
    def test_input_notdict(self):
        response = p_b_h.get_val_from_list(self.input, "actor", "doesnotexist", "noExceptionRaised")
        should_be = set()
        self.assertCountEqual(response, should_be)


class TestBoxParseAdditionalDetails(unittest.TestCase):
    def setUp(self):
        self.initial_dict = {"t": 10, "a": [{"b": 1, "c": 2}], "d": {"e": {"f": True}}}
        self.initial_list = ["1", 2, True, False]
        self.initial_bytes = b'{"t": 10, "a": [{"b": 1, "c": 2}], "d": {"e": {"f": True}}}'
        self.initial_str = '{"t": 10, "a": [{"b": 1, "c": 2}], "d": {"e": {"f": true}}}'
        self.initial_str_no_json = "this is a plain string"
        self.initial_str_list_json = "[1, 2, 3, 4]"

    def test_additional_details_string(self):
        event = {"additional_details": self.initial_str}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(returns.get("t", 0), 10)

    # in the case of a byte array, we expect the empty dict
    def test_additional_details_bytes(self):
        event = {"additional_details": self.initial_bytes}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(len(returns), 0)

    # In the case of a list ( not a string or bytes array ), expect un-altered return
    def test_additional_details_list(self):
        event = {"additional_details": self.initial_list}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(len(returns), 4)

    # in the case of a dict or similar, we expect it to be returned un-altered
    def test_additional_details_dict(self):
        event = {"additional_details": self.initial_dict}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(returns.get("t", 0), 10)

    # If it's a string with no json object to be decoded, we expect an empty dict back
    def test_additional_details_plain_str(self):
        event = {"additional_details": self.initial_str_no_json}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(len(returns), 0)

    # If it's a string with a json list, we expect the list
    def test_additional_details_str_list_json(self):
        event = {"additional_details": self.initial_str_list_json}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(len(returns), 4)


class TestTorExitNodes(unittest.TestCase):
    def test_ip_address_not_found(self):
        """Should not find anything"""
        tor_exit_nodes = p_tor_h.TorExitNodes({})
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_has_exit_nodes_found(self):
        """Should find enrichment"""
        tor_exit_nodes = p_tor_h.TorExitNodes(
            {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}
        )
        self.assertEqual(tor_exit_nodes.has_exit_nodes(), True)

    def test_has_exit_nodes_not_found(self):
        """Should NOT find enrichment"""
        tor_exit_nodes = p_tor_h.TorExitNodes({"p_enrichment": {}})
        self.assertEqual(tor_exit_nodes.has_exit_nodes(), False)

    def test_ip_address_found(self):
        """Should find enrichment"""
        tor_exit_nodes = p_tor_h.TorExitNodes(
            {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}
        )
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, "1.2.3.4")

    def test_url(self):
        """url generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(
            {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}
        )
        url = tor_exit_nodes.url("foo")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        # pylint: disable=line-too-long
        self.assertEqual(
            url,
            f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
        )

    def test_context(self):
        """context generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(
            {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}
        )
        context = tor_exit_nodes.context("foo")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        self.assertEqual(
            context,
            {
                "IP": "1.2.3.4",
                # pylint: disable=line-too-long
                "ExoneraTorURL": f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
            },
        )


class TestIpInfoHelpersLocation(unittest.TestCase):
    def setUp(self):
        self.match_field = "clientIp"
        self.event = {
            "p_enrichment": {
                p_i_h.IPINFO_LOCATION_LUT_NAME: {
                    self.match_field: {
                        "city": "Constantinople",
                        "country": "Byzantium",
                        "lat": "41.008610",
                        "lng": "28.971111",
                        "postal_code": "NA",
                        "region": "Asia Minor",
                        "region_code": "123",
                        "timezone": "GMT+03:00"
                    }   
                }
            }
        }
        self.ip_info = p_i_h.get_ipinfo_location_object(self.event)

    def test_city(self):
        city = self.ip_info.city(self.match_field)
        self.assertEqual(city, "Constantinople")

    def test_country(self):
        country = self.ip_info.country(self.match_field)
        self.assertEqual(country, "Byzantium")

    def test_latitude(self):
        latitude = self.ip_info.latitude(self.match_field)
        self.assertEqual(latitude, "41.008610")

    def test_longitude(self):
        longitude = self.ip_info.longitude(self.match_field)
        self.assertEqual(longitude, "28.971111")

    def test_postal_code(self):
        postal_code = self.ip_info.postal_code(self.match_field)
        self.assertEqual(postal_code, "NA")

    def test_region(self):
        region = self.ip_info.region(self.match_field)
        self.assertEqual(region, "Asia Minor")

    def test_region_code(self):
        region_code = self.ip_info.region_code(self.match_field)
        self.assertEqual(region_code, "123")

    def test_timezone(self):
        timezone = self.ip_info.timezone(self.match_field)
        self.assertEqual(timezone, "GMT+03:00")

    def test_not_found(self):
        self.assertEqual(self.ip_info.timezone("not_found"), None)

    def test_context(self):
        expected = {
            "City": "Constantinople",
            "Country": "Byzantium",
            "Latitude": "41.008610",
            "Longitude": "28.971111",
            "PostalCode": "NA",
            "Region": "Asia Minor",
            "RegionCode": "123",
            "Timezone": "GMT+03:00",
        }
        self.assertEqual(
            expected, self.ip_info.context(self.match_field)
        )


class TestIpInfoHelpersASN(unittest.TestCase):
    def setUp(self):
        self.match_field = "clientIp"
        self.event = {
            "p_enrichment": {
                p_i_h.IPINFO_ASN_LUT_NAME: {
                    self.match_field: {
                        "asn": "AS00000",
                        "domain": "byzantineempire.com",
                        "name": "Byzantine Empire",
                        "route": "1.2.3.4/24",
                        "type": "isp"
                    }
                }
            }
        }
        self.ip_info = p_i_h.get_ipinfo_asn_object(self.event)

    def test_asn(self):
        asn = self.ip_info.asn(self.match_field)
        self.assertEqual(asn, "AS00000")

    def test_domain(self):
        domain = self.ip_info.domain(self.match_field)
        self.assertEqual(domain, "byzantineempire.com")

    def test_name(self):
        name = self.ip_info.name(self.match_field)
        self.assertEqual(name, "Byzantine Empire")

    def test_route(self):
        route = self.ip_info.route(self.match_field)
        self.assertEqual(route, "1.2.3.4/24")

    def test_type(self):
        _type = self.ip_info.type(self.match_field)
        self.assertEqual(_type, "isp")

    def test_not_found(self):
        self.assertEqual(self.ip_info.type("not_found"), None)

    def test_context(self):
        expected = {
            "ASN": "AS00000",
            "Domain": "byzantineempire.com",
            "Name": "Byzantine Empire",
            "Route": "1.2.3.4/24",
            "Type": "isp"
        }
        self.assertEqual(expected, self.ip_info.context(self.match_field))


class TestGeoInfoFromIP(unittest.TestCase):
    def setUp(self):
        self.match_field = "clientIp"
        self.event = {
            "p_enrichment": {
                p_i_h.IPINFO_ASN_LUT_NAME: {
                    self.match_field: {
                        "asn": "AS00000",
                        "domain": "byzantineempire.com",
                        "name": "Byzantine Empire",
                        "route": "1.2.3.4/24",
                        "type": "isp"
                    }
                },
                p_i_h.IPINFO_LOCATION_LUT_NAME: {
                    self.match_field: {
                        "city": "Constantinople",
                        "country": "Byzantium",
                        "lat": "41.008610",
                        "lng": "28.971111",
                        "postal_code": "NA",
                        "region": "Asia Minor",
                        "region_code": "123",
                        "timezone": "GMT+03:00"
                    }   
                }
            },
            self.match_field: "1.2.3.4",
        }

    def test_geoinfo(self):
        geoinfo = p_i_h.geoinfo_from_ip(self.event, self.match_field)
        expected = {
            "city": "Constantinople",
            "country": "Byzantium",
            "ip": "1.2.3.4",
            "loc": "41.008610,28.971111",
            "org": "AS00000 Byzantine Empire",
            "postal": "NA",
            "region": "Asia Minor",
            "timezone": "GMT+03:00"
        }
        self.assertEqual(expected, geoinfo)

    def test_ipinfo_not_enabled_exception(self):
        event = {"p_enrichment": {}}
        with self.assertRaises(p_i_h.PantherIPInfoException) as e:
            p_i_h.geoinfo_from_ip(event, "fake_field")
        
        self.assertEqual(e.exception.args[0], "Please enable both IPInfo Location and ASN Enrichment Providers")

    def test_ipinfo_missing_match_exception(self):
        with self.assertRaises(p_i_h.PantherIPInfoException) as e:
            p_i_h.geoinfo_from_ip(self.event, "fake_field")
        
        self.assertEqual(e.exception.args[0], "IPInfo is not configured on the provided match_field: fake_field")



if __name__ == "__main__":
    unittest.main()
