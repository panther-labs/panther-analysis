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
import panther_greynoise_helpers as p_g_h  # pylint: disable=C0413


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


class TestGreyNoiseHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self.test_data_str_advanced = {
            "ip_address": "2.2.2.2",
            "request_user": "test",
            "request_time": "time",
            "p_enrichment": {
                "greynoise_noise_advanced": {
                    "p_any_ip_addresses": {
                        "actor": "unknown",
                        "ip": "8.8.8.8",
                        "classification": "unknown",
                    },
                }
            },
        }
        self.test_data_list_advanced = {
            "ip_address": "2.2.2.2",
            "request_user": "test",
            "request_time": "time",
            "p_enrichment": {
                "greynoise_noise_advanced": {
                    "p_any_ip_addresses": [
                        "1.2.3.4",
                        "0.6.5.4",
                        "9.8.7.6",
                    ]
                }
            },
        }
        self.test_data_str_basic = {
            "ip_address": "2.2.2.2",
            "request_user": "test",
            "request_time": "time",
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "p_any_ip_addresses": {
                        "actor": "unknown",
                        "ip": "8.8.8.8",
                        "classification": "unknown",
                    },
                }
            },
        }
        self.test_data_list_basic = {
            "ip_address": "2.2.2.2",
            "request_user": "test",
            "request_time": "time",
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "p_any_ip_addresses": [
                        "1.2.3.4",
                        "0.6.5.4",
                        "9.8.7.6",
                    ]
                }
            },
        }

    def test_addresses_adv(self):
        noise = p_g_h.GetGreyNoiseObject(self.test_data_list_advanced)
        exception = p_b_h.PantherIncorrectIPAddressMethodException
        with self.assertRaises(exception):
            noise.ip_address("p_any_ip_addresses")

        assert isinstance(noise.ip_addresses("p_any_ip_addresses"), list)

    def test_address_adv(self):
        noise = p_g_h.GetGreyNoiseObject(self.test_data_str_advanced)
        exception = p_b_h.PantherIncorrectIPAddressMethodException
        with self.assertRaises(exception):
            noise.ip_addresses("p_any_ip_addresses")

        assert isinstance(noise.ip_address("p_any_ip_addresses"), str)

    def test_addresses(self):
        noise = p_g_h.GetGreyNoiseObject(self.test_data_list_basic)
        exception = p_b_h.PantherIncorrectIPAddressMethodException
        with self.assertRaises(exception):
            noise.ip_address("p_any_ip_addresses")

        assert isinstance(noise.ip_addresses("p_any_ip_addresses"), list)

    def test_address(self):
        noise = p_g_h.GetGreyNoiseObject(self.test_data_str_basic)
        exception = p_b_h.PantherIncorrectIPAddressMethodException
        with self.assertRaises(exception):
            noise.ip_addresses("p_any_ip_addresses")

        assert isinstance(noise.ip_address("p_any_ip_addresses"), str)


if __name__ == "__main__":
    unittest.main()
