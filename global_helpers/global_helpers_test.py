#!/usr/bin/env python
# Unit tests for functions inside global_helpers

# pylint: disable=C0302 (too-many-lines)

import datetime
import os
import random
import secrets
import string
import sys
import unittest

import boto3
from moto import mock_dynamodb

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))

import panther_asana_helpers as p_a_h  # pylint: disable=C0413
import panther_auth0_helpers as p_auth0_h  # pylint: disable=C0413
import panther_base_helpers as p_b_h  # pylint: disable=C0413
import panther_cloudflare_helpers as p_cf_h  # pylint: disable=C0413
import panther_greynoise_helpers as p_greynoise_h  # pylint: disable=C0413
import panther_ipinfo_helpers as p_i_h  # pylint: disable=C0413
import panther_notion_helpers as p_notion_h  # pylint: disable=C0413
import panther_oss_helpers as p_o_h  # pylint: disable=C0413
import panther_snyk_helpers as p_snyk_h  # pylint: disable=C0413
import panther_tines_helpers as p_tines_h  # pylint: disable=C0413
import panther_tor_helpers as p_tor_h  # pylint: disable=C0413

# pylint: disable=too-many-lines


class TestEksPantherObjRef(unittest.TestCase):
    def setUp(self):
        # pylint: disable=C0301
        self.event = {
            "annotations": {
                "authorization.k8s.io/decision": "allow",
                "authorization.k8s.io/reason": "",
            },
            "apiVersion": "audit.k8s.io/v1",
            "auditID": "35506555-dffc-4337-b2b1-c4af52b88e18",
            "kind": "Event",
            "level": "Request",
            "objectRef": {
                "apiVersion": "v1",
                "name": "some-job-xxx1y",
                "namespace": "default",
                "resource": "pods",
                "subresource": "log",
            },
            "p_any_aws_account_ids": ["123412341234"],
            "p_any_aws_arns": [
                "arn:aws:iam::123412341234:role/KubeAdministrator",
                "arn:aws:sts::123412341234:assumed-role/KubeAdministrator/1669660343296132000",
            ],
            "p_any_ip_addresses": ["5.5.5.5"],
            "p_any_usernames": ["kubernetes-admin"],
            "p_event_time": "2022-11-29 00:09:04.38",
            "p_log_type": "Amazon.EKS.Audit",
            "p_parse_time": "2022-11-29 00:10:25.067",
            "p_row_id": "2e4ab474b0f0f7a4a8fff4f014aab32a",
            "p_source_id": "4c859cd4-9406-469b-9e0e-c2dc1bee24fa",
            "p_source_label": "example-cluster-eks-logs",
            "requestReceivedTimestamp": "2022-11-29 00:09:04.38",
            "requestURI": "/api/v1/namespaces/default/pods/kube-bench-drn4j/log?container=kube-bench",
            "responseStatus": {"code": 200},
            "sourceIPs": ["5.5.5.5"],
            "stage": "ResponseComplete",
            "stageTimestamp": "2022-11-29 00:09:04.394",
            "user": {
                "extra": {
                    "accessKeyId": ["ASIARLIVEKVNNXXXXXXX"],
                    "arn": [
                        "arn:aws:sts::123412341234:assumed-role/KubeAdministrator/1669660343296132000"
                    ],
                    "canonicalArn": ["arn:aws:iam::123412341234:role/KubeAdministrator"],
                    "sessionName": ["1669660343296132000"],
                },
                "groups": ["system:masters", "system:authenticated"],
                "uid": "aws-iam-authenticator:123412341234:AROARLIVEXXXXXXXXXXXX",
                "username": "kubernetes-admin",
            },
            "userAgent": "kubectl/v1.25.4 (darwin/arm64) kubernetes/872a965",
            "verb": "get",
        }

    def test_complete_event(self):
        response = p_b_h.eks_panther_obj_ref(self.event)
        self.assertEqual(response.get("actor", ""), "kubernetes-admin")
        self.assertEqual(response.get("object", ""), "some-job-xxx1y")
        self.assertEqual(response.get("ns", ""), "default")
        self.assertEqual(len(response.get("sourceIPs", [])), 1)
        self.assertEqual(response.get("sourceIPs", [])[0], "5.5.5.5")
        self.assertEqual(response.get("resource", ""), "pods/log")
        self.assertEqual(response.get("verb", ""), "get")
        self.assertEqual(response.get("p_source_label", ""), "example-cluster-eks-logs")

    def test_all_missing_event(self):
        del self.event["user"]["username"]
        del self.event["objectRef"]
        del self.event["sourceIPs"]
        del self.event["verb"]
        del self.event["p_source_label"]
        response = p_b_h.eks_panther_obj_ref(self.event)
        self.assertEqual(response.get("actor", ""), "<NO_USERNAME>")
        self.assertEqual(response.get("object", ""), "<NO_OBJECT_NAME>")
        self.assertEqual(response.get("ns", ""), "<NO_OBJECT_NAMESPACE>")
        self.assertEqual(len(response.get("sourceIPs", [])), 1)
        self.assertEqual(response.get("sourceIPs", [])[0], "0.0.0.0")  # nosec
        self.assertEqual(response.get("resource", ""), "<NO_OBJECT_RESOURCE>")
        self.assertEqual(response.get("verb", ""), "<NO_VERB>")
        self.assertEqual(response.get("p_source_label", ""), "<NO_P_SOURCE_LABEL>")

    def test_missing_subresource_event(self):
        del self.event["objectRef"]["subresource"]
        response = p_b_h.eks_panther_obj_ref(self.event)
        self.assertEqual(response.get("resource", ""), "pods")


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
    def setUp(self):
        self.event = {"p_enrichment": {"tor_exit_nodes": {"foo": {"ip": "1.2.3.4"}}}}

        # match against array field
        self.event_list = {
            "p_enrichment": {
                "tor_exit_nodes": {"p_any_ip_addresses": [{"ip": "1.2.3.4"}, {"ip": "1.2.3.5"}]}
            }
        }

    def test_ip_address_not_found(self):
        """Should not find anything"""
        tor_exit_nodes = p_tor_h.TorExitNodes({})
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, None)
        self.assertEqual(tor_exit_nodes.has_exit_nodes(), False)

    def test_ip_address_found(self):
        """Should find enrichment"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
        ip_address = tor_exit_nodes.ip_address("foo")
        self.assertEqual(ip_address, "1.2.3.4")
        self.assertEqual(tor_exit_nodes.has_exit_nodes(), True)

    def test_ip_address_found_list(self):
        """Should find enrichment list"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event_list)
        ip_address_list = tor_exit_nodes.ip_address("p_any_ip_addresses")
        self.assertEqual(ip_address_list, ["1.2.3.4", "1.2.3.5"])
        self.assertEqual(tor_exit_nodes.has_exit_nodes(), True)

    def test_url(self):
        """url generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
        url = tor_exit_nodes.url("foo")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        # pylint: disable=line-too-long
        self.assertEqual(
            url,
            f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
        )

    def test_url_list(self):
        """url generation list"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event_list)
        urls = tor_exit_nodes.url("p_any_ip_addresses")
        today = datetime.datetime.today().strftime("%Y-%m-%d")
        # pylint: disable=line-too-long
        self.assertEqual(
            urls,
            [
                f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.4&timestamp={today}&lang=en",
                f"https://metrics.torproject.org/exonerator.html?ip=1.2.3.5&timestamp={today}&lang=en",
            ],
        )

    def test_context(self):
        """context generation"""
        tor_exit_nodes = p_tor_h.TorExitNodes(self.event)
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


class TestGreyNoiseBasic(unittest.TestCase):
    def setUp(self):
        self.event = {
            "p_enrichment": {
                "greynoise_noise_basic": {
                    "ClientIP": {
                        "actor": "unknown",
                        "classification": "malicious",
                        "ip": "142.93.204.250",
                    }
                }
            }
        }

    def test_greynoise_object(self):
        """Should be basic"""
        noise = p_greynoise_h.GetGreyNoiseObject(self.event)
        self.assertEqual(noise.subscription_level(), "basic")

    def test_greynoise_severity(self):
        """Should be CRITICAL"""
        sev = p_greynoise_h.GreyNoiseSeverity(self.event, "ClientIP")
        self.assertEqual(sev, "CRITICAL")

    def test_subscription_level(self):
        """Should be basic"""
        noise = p_greynoise_h.GreyNoiseBasic({})
        self.assertEqual(noise.subscription_level(), "basic")

    def test_ip_address_not_found(self):
        """Should not find anything"""
        noise = p_greynoise_h.GreyNoiseBasic({})
        ip_address = noise.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_ip_address_found(self):
        """Should find enrichment"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        ip_address = noise.ip_address("ClientIP")
        self.assertEqual(ip_address, "142.93.204.250")

    def test_classification(self):
        """Should classify as malicious"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        classification = noise.classification("ClientIP")
        self.assertEqual(classification, "malicious")

    def test_actor(self):
        """Should have unknown actor"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        actor = noise.actor("ClientIP")
        self.assertEqual(actor, "unknown")

    def test_url(self):
        """Should have url"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        url = noise.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_context(self):
        """context generation"""
        noise = p_greynoise_h.GreyNoiseBasic(self.event)
        context = noise.context("ClientIP")
        self.assertEqual(
            context,
            {
                "Actor": "unknown",
                "Classification": "malicious",
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250",
            },
        )


# pylint: disable=too-many-public-methods
class TestGreyNoiseAdvanced(unittest.TestCase):
    def setUp(self):
        self.event = {
            "p_enrichment": {
                "greynoise_noise_advanced": {
                    "ClientIP": {
                        "actor": "unknown",
                        "bot": False,
                        "classification": "malicious",
                        "cve": ["cve1244", "cve4567"],
                        "first_seen": "2022-03-19",
                        "ip": "142.93.204.250",
                        "last_seen_timestamp": "2022-04-06",
                        "metadata": {
                            "asn": "AS14061",
                            "category": "hosting",
                            "city": "North Bergen",
                            "country": "United States",
                            "country_code": "US",
                            "organization": "DigitalOcean, LLC",
                            "os": "Linux 2.2-3.x",
                            "rdns": "",
                            "region": "New Jersey",
                            "tor": False,
                        },
                        "raw_data": {
                            "hassh": [],
                            "ja3": [],
                            "scan": [{"port": 23, "protocol": "TCP"}],
                            "web": {},
                        },
                        "seen": True,
                        "spoofable": False,
                        "tags": ["Mirai", "ZMap Client"],
                        "vpn": False,
                        "vpn_service": "N/A",
                    }
                }
            }
        }

        self.event_list = {
            "p_enrichment": {
                "greynoise_noise_advanced": {
                    "p_any_ip_addresses": [
                        {
                            "actor": "unknown",
                            "bot": False,
                            "classification": "malicious",
                            "cve": ["cve1244", "cve4567"],
                            "first_seen": "2022-03-19",
                            "ip": "142.93.204.250",
                            "last_seen_timestamp": "2022-04-06",
                            "metadata": {
                                "asn": "AS14061",
                                "category": "hosting",
                                "city": "North Bergen",
                                "country": "United States",
                                "country_code": "US",
                                "organization": "DigitalOcean, LLC",
                                "os": "Linux 2.2-3.x",
                                "rdns": "",
                                "region": "New Jersey",
                                "tor": False,
                            },
                            "raw_data": {
                                "hassh": [],
                                "ja3": [],
                                "scan": [{"port": 23, "protocol": "TCP"}],
                                "web": {},
                            },
                            "seen": True,
                            "spoofable": False,
                            "tags": ["Mirai", "ZMap Client"],
                            "vpn": False,
                            "vpn_service": "N/A",
                        },
                        {
                            "actor": "stinky rat",
                            "bot": True,
                            "classification": "malicious",
                            "cve": ["cve1244", "cve4567"],
                            "first_seen": "2022-02-19",
                            "ip": "100.93.204.250",
                            "last_seen_timestamp": "2022-03-06",
                            "metadata": {
                                "asn": "AS14461",
                                "category": "isp",
                                "city": "South Bergen",
                                "country": "United States",
                                "country_code": "US",
                                "organization": "DigitalOcean, LLC",
                                "os": "Linux 2.2-3.x",
                                "rdns": "",
                                "region": "South Hampton",
                                "tor": False,
                            },
                            "spoofable": False,
                            "vpn": False,
                            "vpn_service": "N/A",
                        },
                    ]
                }
            }
        }

    def test_greynoise_object(self):
        """Should be advanced"""
        noise = p_greynoise_h.GetGreyNoiseObject(self.event)
        self.assertEqual(noise.subscription_level(), "advanced")

    def test_greynoise_severity(self):
        """Should be CRITICAL"""
        sev = p_greynoise_h.GreyNoiseSeverity(self.event, "ClientIP")
        self.assertEqual(sev, "CRITICAL")

    def test_greynoise_severity_list(self):
        """Should be CRITICAL (list)"""
        sev = p_greynoise_h.GreyNoiseSeverity(self.event_list, "p_any_ip_addresses")
        self.assertEqual(sev, "CRITICAL")

    def test_subscription_level(self):
        """Should be advanced"""
        noise = p_greynoise_h.GreyNoiseAdvanced({})
        self.assertEqual(noise.subscription_level(), "advanced")

    def test_ip_address_not_found(self):
        """Should not find anything"""
        noise = p_greynoise_h.GreyNoiseAdvanced({})
        ip_address = noise.ip_address("foo")
        self.assertEqual(ip_address, None)

    def test_ip_address_found(self):
        """Should find enrichment"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        ip_address = noise.ip_address("ClientIP")
        self.assertEqual(ip_address, "142.93.204.250")

    def test_classification(self):
        """Should classify as malicious"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        classification = noise.classification("ClientIP")
        self.assertEqual(classification, "malicious")

    def test_actor(self):
        """Should have unknown actor"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        actor = noise.actor("ClientIP")
        self.assertEqual(actor, "unknown")

    def test_url(self):
        """Should have url"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        url = noise.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_is_bot(self):
        """Should be bot"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_bot = noise.is_bot("ClientIP")
        self.assertEqual(is_bot, False)

    def test_cve_string(self):
        """Should have cve string"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        cve_string = noise.cve_string("ClientIP")
        self.assertEqual(cve_string, "cve1244 cve4567")

    def test_cve_list(self):
        """Should have cve list"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        cve_list = noise.cve_list("ClientIP")
        self.assertEqual(cve_list, ["cve1244", "cve4567"])

    def test_first_seen(self):
        """Should have first seen"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        first_seen = noise.first_seen("ClientIP")
        self.assertEqual(first_seen, datetime.datetime(2022, 3, 19, 0, 0))

    def test_first_seen_list(self):
        """Should have first seen (list)"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event_list)
        first_seen = noise.first_seen("p_any_ip_addresses")
        self.assertEqual(first_seen, datetime.datetime(2022, 2, 19, 0, 0))

    def test_last_seen(self):
        """Should have last seen"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        last_seen = noise.last_seen("ClientIP")
        self.assertEqual(last_seen, datetime.datetime(2022, 4, 6, 0, 0))

    def test_last_seen_list(self):
        """Should have last seen (list)"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event_list)
        last_seen = noise.last_seen("p_any_ip_addresses")
        self.assertEqual(last_seen, datetime.datetime(2022, 4, 6, 0, 0))

    def test_asn(self):
        """Should have asn"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        asn = noise.asn("ClientIP")
        self.assertEqual(asn, "AS14061")

    def test_category(self):
        """Should have catgeory"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        category = noise.category("ClientIP")
        self.assertEqual(category, "hosting")

    def test_city(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        city = noise.city("ClientIP")
        self.assertEqual(city, "North Bergen")

    def test_country(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        country = noise.country("ClientIP")
        self.assertEqual(country, "United States")

    def test_country_code(self):
        """Should have city"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        country_code = noise.country_code("ClientIP")
        self.assertEqual(country_code, "US")

    def test_organization(self):
        """Should have organization"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        organization = noise.organization("ClientIP")
        self.assertEqual(organization, "DigitalOcean, LLC")

    def test_operating_system(self):
        """Should have os"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        operating_system = noise.operating_system("ClientIP")
        self.assertEqual(operating_system, "Linux 2.2-3.x")

    def test_region(self):
        """Should have region"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        region = noise.region("ClientIP")
        self.assertEqual(region, "New Jersey")

    def test_is_tor(self):
        """Should not have tor"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_tor = noise.is_tor("ClientIP")
        self.assertEqual(is_tor, False)

    def test_rev_dns(self):
        """Should not have rev dns"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        rev_dns = noise.rev_dns("ClientIP")
        self.assertEqual(rev_dns, "")

    def test_is_spoofable(self):
        """Should not be spoofable"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_spoofable = noise.is_spoofable("ClientIP")
        self.assertEqual(is_spoofable, False)

    def test_tags_string(self):
        """Should have tags string"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        tags_string = noise.tags_string("ClientIP")
        self.assertEqual(tags_string, "Mirai ZMap Client")

    def test_tags_list(self):
        """Should have tags list"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        tags_list = noise.tags_list("ClientIP")
        self.assertEqual(tags_list, ["Mirai", "ZMap Client"])

    def test_is_vpn(self):
        """Should not be vpn"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        is_vpn = noise.is_vpn("ClientIP")
        self.assertEqual(is_vpn, False)

    def test_vpn_service(self):
        """Should not be vpn service"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        vpn_service = noise.vpn_service("ClientIP")
        self.assertEqual(vpn_service, "N/A")

    def test_metadata(self):
        """Should have metadata"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        metadata = noise.metadata("ClientIP")
        self.assertEqual(
            metadata,
            {
                "asn": "AS14061",
                "category": "hosting",
                "city": "North Bergen",
                "country": "United States",
                "country_code": "US",
                "organization": "DigitalOcean, LLC",
                "os": "Linux 2.2-3.x",
                "rdns": "",
                "region": "New Jersey",
                "tor": False,
            },
        )

    def test_context(self):
        """context generation"""
        noise = p_greynoise_h.GreyNoiseAdvanced(self.event)
        context = noise.context("ClientIP")
        self.assertEqual(
            context,
            {
                "Actor": "unknown",
                "Classification": "malicious",
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250",
                "Metadata": {
                    "asn": "AS14061",
                    "category": "hosting",
                    "city": "North Bergen",
                    "country": "United States",
                    "country_code": "US",
                    "organization": "DigitalOcean, LLC",
                    "os": "Linux 2.2-3.x",
                    "rdns": "",
                    "region": "New Jersey",
                    "tor": False,
                },
                "VPN": "N/A",
                "Tags": ["Mirai", "ZMap Client"],
                "CVE": ["cve1244", "cve4567"],
            },
        )


class TestRIOTBasic(unittest.TestCase):
    def setUp(self):
        self.event = {
            "p_enrichment": {
                "greynoise_riot_basic": {
                    "ClientIP": {
                        "ip_cidr": "142.93.204.250/32",
                        "provider": {"name": "foo"},
                        "scan_time": "2023-05-12 05:11:04.679962983",
                    }
                }
            }
        }

    def test_greynoise_object(self):
        """Should be basic"""
        riot = p_greynoise_h.GetGreyNoiseRiotObject(self.event)
        self.assertEqual(riot.subscription_level(), "basic")

    def test_subscription_level(self):
        """Should be basic"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic({})
        self.assertEqual(riot.subscription_level(), "basic")

    def test_greynoise_severity(self):
        """Should be INFO"""
        sev = p_greynoise_h.GreyNoiseSeverity(self.event, "ClientIP")
        self.assertEqual(sev, "INFO")

    def test_is_riot(self):
        """Should be riot"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        is_riot = riot.is_riot("ClientIP")
        self.assertEqual(is_riot, True)

    def test_ip_address(self):
        """Should have ip address"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        cidr = riot.ip_address("ClientIP")
        self.assertEqual(cidr, "142.93.204.250/32")

    def test_name(self):
        """Should have name"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        name = riot.name("ClientIP")
        self.assertEqual(name, "foo")

    def test_url(self):
        """Should have url"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        url = riot.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_last_updated(self):
        """Should have last_updated"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        last_udpated = riot.last_updated("ClientIP")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_context(self):
        """Should have context"""
        riot = p_greynoise_h.GreyNoiseRIOTBasic(self.event)
        context = riot.context("ClientIP")
        self.assertEqual(
            context,
            {
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250/32",
                "Is_RIOT": True,
                "Name": "foo",
            },
        )


class TestRIOTAdvanced(unittest.TestCase):
    def setUp(self):
        self.event = {
            "p_enrichment": {
                "greynoise_riot_advanced": {
                    "ClientIP": {
                        "ip_cidr": "142.93.204.250/32",
                        "provider": {
                            "name": "foo",
                            "category": "cloud",
                            "description": "some cloud",
                            "explanation": "because",
                            "reference": "my brother",
                            "trust_level": "1",
                        },
                        "scan_time": "2023-05-12 05:11:04.679962983",
                    }
                }
            }
        }

        # for testing array matches
        self.event_list = {
            "p_enrichment": {
                "greynoise_riot_advanced": {
                    "p_any_ip_addresses": [
                        {
                            "ip_cidr": "142.93.204.250/32",
                            "provider": {
                                "name": "foo",
                                "category": "cloud",
                                "description": "some cloud",
                                "explanation": "because",
                                "reference": "my brother",
                                "trust_level": "1",
                            },
                            "scan_time": "2023-05-12 05:11:04.679962983",
                        },
                        {
                            "ip_cidr": "142.93.204.128/32",
                            "provider": {
                                "name": "bar",
                                "category": "cdn",
                                "description": "some some cdn",
                                "explanation": "because",
                                "reference": "my brother",
                                "trust_level": "2",
                            },
                            "scan_time": "2023-05-11 05:11:04.679962983",
                        },
                    ]
                }
            }
        }

    def test_greynoise_object(self):
        """Should be advanced"""
        riot = p_greynoise_h.GetGreyNoiseRiotObject(self.event)
        self.assertEqual(riot.subscription_level(), "advanced")

    def test_subscription_level(self):
        """Should be advanced"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced({})
        self.assertEqual(riot.subscription_level(), "advanced")

    def test_greynoise_severity(self):
        """Should be INFO"""
        sev = p_greynoise_h.GreyNoiseSeverity(self.event, "ClientIP")
        self.assertEqual(sev, "INFO")

    def test_is_riot(self):
        """Should be riot"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        is_riot = riot.is_riot("ClientIP")
        self.assertEqual(is_riot, True)

    def test_ip_address(self):
        """Should have ip address"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        cidr = riot.ip_address("ClientIP")
        self.assertEqual(cidr, "142.93.204.250/32")

    def test_name(self):
        """Should have name"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        name = riot.name("ClientIP")
        self.assertEqual(name, "foo")

    def test_url(self):
        """Should have url"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        url = riot.url("ClientIP")
        self.assertEqual(url, "https://www.greynoise.io/viz/ip/142.93.204.250")

    def test_last_updated(self):
        """Should have last_updated"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        last_udpated = riot.last_updated("ClientIP")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_last_updated_list(self):
        """Should have last_updated (list)"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event_list)
        last_udpated = riot.last_updated("p_any_ip_addresses")
        self.assertEqual(last_udpated, datetime.datetime(2023, 5, 12, 5, 11, 4, 679962))

    def test_description(self):
        """Should have description"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        desc = riot.description("ClientIP")
        self.assertEqual(desc, "some cloud")

    def test_category(self):
        """Should have category"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        cat = riot.category("ClientIP")
        self.assertEqual(cat, "cloud")

    def test_explanation(self):
        """Should have explanation"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        exp = riot.explanation("ClientIP")
        self.assertEqual(exp, "because")

    def test_reference(self):
        """Should have reference"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        ref = riot.reference("ClientIP")
        self.assertEqual(ref, "my brother")

    def test_trust_level(self):
        """Should have trust_level"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        trust_level = riot.trust_level("ClientIP")
        self.assertEqual(trust_level, "1")

    def test_trust_level_list(self):
        """Should have trust_level (list)"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event_list)
        levels = riot.trust_level("p_any_ip_addresses")
        self.assertEqual(levels, ["1", "2"])

    def test_context(self):
        """Should have context"""
        riot = p_greynoise_h.GreyNoiseRIOTAdvanced(self.event)
        context = riot.context("ClientIP")
        self.assertEqual(
            context,
            {
                "GreyNoise_URL": "https://www.greynoise.io/viz/ip/142.93.204.250",
                "IP": "142.93.204.250/32",
                "Is_RIOT": True,
                "Name": "foo",
                "Provider Data": {
                    "name": "foo",
                    "category": "cloud",
                    "description": "some cloud",
                    "explanation": "because",
                    "reference": "my brother",
                    "trust_level": "1",
                },
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
                        "timezone": "GMT+03:00",
                    }
                }
            }
        }
        self.ip_info = p_i_h.get_ipinfo_location(self.event)

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
        self.assertEqual(expected, self.ip_info.context(self.match_field))


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
                        "type": "isp",
                    }
                }
            }
        }
        self.ip_info = p_i_h.get_ipinfo_asn(self.event)

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
            "Type": "isp",
        }
        self.assertEqual(expected, self.ip_info.context(self.match_field))


class TestFilterCrowdStrikeFdrEventType(unittest.TestCase):
    def setUp(self):
        self.input = {
            "p_log_type": "Crowdstrike.FDREvent",
            "aid": "else",
            "event": {"foo": "bar"},
            "fdr_event_type": "DnsRequest",
        }

    def test_is_different_with_fdr_event_type_provided(self):
        response = p_b_h.filter_crowdstrike_fdr_event_type(self.input, "SomethingElse")
        self.assertEqual(response, True)

    def test_is_same_with_the_fdr_event_type_provided(self):
        response = p_b_h.filter_crowdstrike_fdr_event_type(self.input, "DnsRequest")
        self.assertEqual(response, False)

    def test_is_entirely_different_type(self):
        self.input = {
            "p_log_type": "Crowdstrike.DnsRequest",
            "aid": "else",
            "event": {"foo": "bar"},
        }
        response = p_b_h.filter_crowdstrike_fdr_event_type(self.input, "DnsRequest")
        self.assertEqual(response, False)


class TestGetCrowdstrikeField(unittest.TestCase):
    def setUp(self):
        self.input = {
            "cid": "something",
            "aid": "else",
            "event": {"foo": "bar"},
            "unknown_payload": {"field": "is"},
        }

    def test_input_key_default_works(self):
        response = p_b_h.get_crowdstrike_field(self.input, "zee", default="hello")
        self.assertEqual(response, "hello")

    def test_input_key_does_not_exist(self):
        response = p_b_h.get_crowdstrike_field(self.input, "zee")
        self.assertEqual(response, None)

    def test_input_key_exists(self):
        response = p_b_h.get_crowdstrike_field(self.input, "cid")
        self.assertEqual(response, "something")

    def test_input_key_can_be_found_in_event(self):
        response = p_b_h.get_crowdstrike_field(self.input, "foo")
        self.assertEqual(response, "bar")

    def test_input_key_can_be_found_in_unknown(self):
        response = p_b_h.get_crowdstrike_field(self.input, "field")
        self.assertEqual(response, "is")

    def test_precedence(self):
        self.input["event"]["field"] = "found"
        response = p_b_h.get_crowdstrike_field(self.input, "field")
        self.assertEqual(response, "found")


class TestIpInfoHelpersPrivacy(unittest.TestCase):
    def setUp(self):
        self.match_field = "clientIp"
        self.event = {
            "p_enrichment": {
                p_i_h.IPINFO_PRIVACY_LUT_NAME: {
                    self.match_field: {
                        "hosting": False,
                        "proxy": False,
                        "tor": False,
                        "vpn": True,
                        "relay": False,
                        "service": "VPN Gate",
                    }
                }
            }
        }
        self.ip_info = p_i_h.get_ipinfo_privacy(self.event)

    def test_hosting(self):
        hosting = self.ip_info.hosting(self.match_field)
        self.assertEqual(hosting, False)

    def test_proxy(self):
        proxy = self.ip_info.proxy(self.match_field)
        self.assertEqual(proxy, False)

    def test_tor(self):
        tor = self.ip_info.tor(self.match_field)
        self.assertEqual(tor, False)

    def test_vpn(self):
        vpn = self.ip_info.vpn(self.match_field)
        self.assertEqual(vpn, True)

    def test_relay(self):
        relay = self.ip_info.relay(self.match_field)
        self.assertEqual(relay, False)

    def test_service(self):
        service = self.ip_info.service(self.match_field)
        self.assertEqual(service, "VPN Gate")

    def test_not_found(self):
        self.assertEqual(self.ip_info.service("not_found"), None)

    def test_context(self):
        expected = {
            "Hosting": False,
            "Proxy": False,
            "Tor": False,
            "VPN": True,
            "Relay": False,
            "Service": "VPN Gate",
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
                        "type": "isp",
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
                        "timezone": "GMT+03:00",
                    }
                },
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
            "timezone": "GMT+03:00",
        }
        self.assertEqual(expected, geoinfo)

    def test_ipinfo_not_enabled_exception(self):
        event = {"p_enrichment": {}}
        with self.assertRaises(p_i_h.PantherIPInfoException) as exc:
            p_i_h.geoinfo_from_ip(event, "fake_field")

        self.assertEqual(
            exc.exception.args[0], "Please enable both IPInfo Location and ASN Enrichment Providers"
        )

    def test_ipinfo_missing_match_exception(self):
        with self.assertRaises(p_i_h.PantherIPInfoException) as exc:
            p_i_h.geoinfo_from_ip(self.event, "fake_field")

        self.assertEqual(
            exc.exception.args[0],
            "IPInfo is not configured on the provided match_field: fake_field",
        )


class TestDeepGet(unittest.TestCase):
    def test_deep_get(self):
        event = {"thing": {"value": "one"}}
        self.assertEqual(p_b_h.deep_get(event, "thing", "value"), "one")
        self.assertEqual(p_b_h.deep_get(event, "thing", "not_exist", default="ok"), "ok")
        event["thing"]["none_val"] = None
        self.assertEqual(p_b_h.deep_get(event, "thing", "none_val", default="ok"), "ok")
        # If the value and the default kwarg are both None, then return None
        self.assertEqual(p_b_h.deep_get(event, "thing", "none_val", default=None), None)
        # If the searched key is not found, and no default kwarg is provided, return None
        self.assertEqual(p_b_h.deep_get(event, "key_does_not_exist"), None)


class TestDeepWalk(unittest.TestCase):
    """
    Test the functionality of the deep_walk function

    This test case has been stress-tested on `max_depth` values of 100 and
    with as many as 100-million iterations (though this is very slow
    due to the complexity of the generated data)

    To ensure relatively quick test runs, keep `max_depth` at <=10
    and test iterations at <=10,000
    """

    # nosec B311
    @staticmethod
    def random_kv_pair() -> dict:
        """
        Generate a random number (`[1,5]`) of key-value pairs for use in nested structures
        generated by `generate_random_test_case_success` and `generate_random_test_case_default`

        The pairs can contain both string and integer values to add another random element to the
        data

        Key specs:
            - String containing `[1,5]` characters

        Value specs:
            - String containing `[1,5]` characters
            - Integer between `0` and `2^32`

        :return dict:
        """
        return {
            "".join(secrets.choice(string.hexdigits) for _ in range(5)): "".join(
                secrets.choice(string.hexdigits) for _ in range(5)
            )
            if secrets.choice([True, False])
            else "".join(secrets.choice(string.digits) for _ in range(10))
            for _ in [secrets.SystemRandom().randrange(1, 5)]
        }

    # nosec B311
    def generate_random_test_case_success(self, max_depth=10):
        """
        Generate data that will always pass

        This method will return a nested data structure of varying depth
        and complexity along with the keys needed to traverse the structure and the expected
        value to check for when calling deep_walk

        :param max_depth:
        :return:
        """

        def _generate(keys=None, depth=0):
            if keys is None:
                keys = []
            kv_pair = self.random_kv_pair()
            key = secrets.choice(list(kv_pair.keys()))
            if depth == max_depth:
                return kv_pair, keys + [key], kv_pair[key]
            nested, keys, expected = _generate(keys + [key], depth + 1)
            kv_pair[key] = nested
            if secrets.choice(["dict", "list"]) == "list":
                kv_pair[key] = [nested for _ in [secrets.SystemRandom().randrange(1, 5)]]
            return kv_pair, keys, expected

        return _generate()

    # nosec B311
    def generate_random_test_case_default(self, depth=0, max_depth=10):
        """
        Generate data that will always return the default value

        This method will return a nested data structure of varying depth
        and complexity but will not return a list of keys used to traverse the structure

        A list of nonexistent keys is returned instead which should not match any of the keys
        in the structure when deep_walk is called

        :param depth:
        :param max_depth:
        :return:
        """

        def _generate():
            kv_pair = self.random_kv_pair()
            key = secrets.choice(list(kv_pair.keys()))
            if secrets.choice(["dict", "list"]) == "list":
                if depth != max_depth:
                    return [{key: self.generate_random_test_case_default(depth + 1, max_depth)}]
                return [kv_pair]
            if depth != max_depth:
                return {key: self.generate_random_test_case_default(depth + 1, max_depth)}
            return kv_pair

        # These keys should not be able to collide with the keys in the generated KV pair
        # To ensure that this is the case, generate [1,max_depth] keys with a lower-bound
        # length greater than the longest key length in the generated structure
        nonexistent_keys = [
            "".join(secrets.choice(string.hexdigits) for _ in range(10))
            for _ in [secrets.SystemRandom().randrange(1, max_depth)]
        ]
        return _generate(), nonexistent_keys

    def test_deep_walk_success_random(self):
        """
        Run one-thousand iterations of the successful test generation code

        The expected value should always be returned by deep_walk for this test case

        :return:
        """
        for _ in range(1000):
            data, keys, expected = self.generate_random_test_case_success()
            self.assertEqual(p_b_h.deep_walk(data, *keys, default=""), expected)

    def test_deep_walk_default_random(self):
        """
        Run one-thousand iterations of the default value test generation code

        The default value should always be returned by deep_walk for this test case

        :return:
        """
        for _ in range(1000):
            data, keys = self.generate_random_test_case_default()
            self.assertEqual(p_b_h.deep_walk(data, *keys, default="NOT FOUND"), "NOT FOUND")

    def test_deep_walk_manual(self):
        """
        Manually test the deep_walk function with a static dictionary with
        various mappings.

        This test case contains expected value and default value cases

        :return:
        """
        event = {
            "key": {
                "inner_key": [{"nested_key": "nested_value"}, {"nested_key": "nested_value2"}],
                "very_nested": [
                    {
                        "outer_key": [
                            {
                                "nested_key": "value",
                                "nested_key2": [{"nested_key3": "value2"}],
                            }
                        ],
                        "outer_key2": [{"nested_key4": "value3"}],
                    }
                ],
                "another_key": "value6",
                "empty_list_key": [],
                "multiple_empty_lists_key1": [[]],
                "multiple_empty_lists_key2": [[[]]],
                "multiple_empty_lists_key3": [[[[[[]]]]]],
                "multiple_nested_lists_with_dict": [[[{"very_nested_key": "very_nested_value"}]]],
                "nested_dict_key": {"nested_dict_value": "value7"},
                "none_value": None,
            }
        }
        self.assertEqual(
            p_b_h.deep_walk(event, "key", "inner_key", "nested_key", default=""), "nested_value2"
        )
        self.assertEqual(
            p_b_h.deep_walk(event, "key", "very_nested", "outer_key", "nested_key", default=""),
            "value",
        )
        self.assertEqual(
            p_b_h.deep_walk(
                event, "key", "very_nested", "outer_key", "nested_key2", "nested_key3", default=""
            ),
            "value2",
        )
        self.assertEqual(
            p_b_h.deep_walk(event, "key", "very_nested", "outer_key2", "nested_key4", default=""),
            "value3",
        )
        self.assertEqual(p_b_h.deep_walk(event, "key", "another_key", default=""), "value6")
        self.assertEqual(p_b_h.deep_walk(event, "key", "empty_list_key", default=""), "")
        self.assertEqual(
            p_b_h.deep_walk(event, "key", "empty_list_key", "nonexistent_key", default=""), ""
        )
        self.assertEqual(p_b_h.deep_walk(event, "key", "multiple_empty_lists_key1", default=""), "")
        self.assertEqual(p_b_h.deep_walk(event, "key", "multiple_empty_lists_key2", default=""), "")
        self.assertEqual(p_b_h.deep_walk(event, "key", "multiple_empty_lists_key3", default=""), "")
        self.assertEqual(
            p_b_h.deep_walk(
                event, "key", "multiple_nested_lists_with_dict", "very_nested_key", default=""
            ),
            "very_nested_value",
        )
        self.assertEqual(
            p_b_h.deep_walk(event, "key", "nested_dict_key", "nested_dict_value", default=""),
            "value7",
        )
        self.assertEqual(p_b_h.deep_walk(event, "key", "none_value", default=""), "")


class TestCloudflareHelpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "Source": "firewallrules",
            "ClientIP": "12.12.12.12",
            "BotScore": 0,
            "Action": "block",
        }
        self.possible_sources = p_cf_h.FIREWALL_SOURCE_MAPPING.keys()
        self.http_event = {
            # pylint: disable=line-too-long
            # ClientUserAgent line is too long
            "CacheCacheStatus": "hit",
            "CacheResponseBytes": 21213,
            "CacheResponseStatus": 200,
            "CacheTieredFill": True,
            "ClientASN": 15169,
            "ClientCountry": "us",
            "ClientDeviceType": "desktop",
            "ClientIP": "12.12.12.12",
            "ClientIPClass": "searchEngine",
            "ClientMTLSAuthCertFingerprint": "",
            "ClientMTLSAuthStatus": "unknown",
            "ClientRequestBytes": 5460,
            "ClientRequestHost": "panther.com",
            "ClientRequestMethod": "GET",
            "ClientRequestPath": "/blog/",
            "ClientRequestProtocol": "HTTP/1.1",
            "ClientRequestReferer": "",
            "ClientRequestScheme": "https",
            "ClientRequestSource": "edgeWorkerFetch",
            "ClientRequestURI": "/blog/",
            "ClientRequestUserAgent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "ClientSSLCipher": "NONE",
            "ClientSSLProtocol": "none",
            "ClientSrcPort": 0,
            "ClientTCPRTTMs": 0,
            "ClientXRequestedWith": "",
            "EdgeCFConnectingO2O": False,
            "EdgeColoCode": "ABC",
            "EdgeColoID": 111,
            "EdgeEndTimestamp": "2022-08-27 22:00:10",
            "EdgePathingOp": "wl",
            "EdgePathingSrc": "macro",
            "EdgePathingStatus": "se",
            "EdgeRateLimitAction": "",
            "EdgeRateLimitID": "0",
            "EdgeRequestHost": "panther.com",
            "EdgeResponseBodyBytes": 76074,
            "EdgeResponseBytes": 77454,
            "EdgeResponseCompressionRatio": 1,
            "EdgeResponseContentType": "text/html",
            "EdgeResponseStatus": 200,
            "EdgeServerIP": "",
            "EdgeStartTimestamp": "2022-08-27 22:00:10",
            "EdgeTimeToFirstByteMs": 82,
            "OriginDNSResponseTimeMs": 0,
            "OriginIP": "",
            "OriginRequestHeaderSendDurationMs": 0,
            "OriginResponseBytes": 0,
            "OriginResponseDurationMs": 70,
            "OriginResponseStatus": 0,
            "OriginResponseTime": 0,
            "OriginSSLProtocol": "unknown",
            "ParentRayID": "7000000000000000",
            "RayID": "7000000000000001",
            "SecurityLevel": "off",
            "SmartRouteColoID": 0,
            "UpperTierColoID": 1,
            "WAFAction": "unknown",
            "WAFFlags": "0",
            "WAFMatchedVar": "xx",
            "WAFProfile": "unknown",
            "WAFRuleID": "xx",
            "WAFRuleMessage": "xx",
            "WorkerCPUTime": 0,
            "WorkerStatus": "unknown",
            "WorkerSubrequest": True,
            "WorkerSubrequestCount": 0,
            "ZoneID": 500000000,
            "ZoneName": "panther.com",
        }

    def test_map_source_to_name(self):
        self.assertEqual(p_cf_h.map_source_to_name(self.event.get("Source")), "Firewall Rules")
        self.assertEqual(p_cf_h.map_source_to_name(self.event), "Firewall Rules")
        self.assertEqual(p_cf_h.map_source_to_name("Does Not Exist"), "Does Not Exist")
        self.assertEqual(p_cf_h.map_source_to_name({}), "<NO_SOURCE>")

    def test_fw_context_helper(self):
        context = p_cf_h.cloudflare_fw_alert_context(self.event)
        self.assertEqual("Firewall Rules", context.get("pan_cf_source"))
        self.event.pop("Source")
        context = p_cf_h.cloudflare_fw_alert_context(self.event)
        self.assertEqual("<Source_NOT_IN_EVENT>", context.get("Source"))
        self.assertEqual("block", context.get("Action"))
        self.assertEqual("12.12.12.12", context.get("ClientIP"))

    def test_http_context_helper(self):
        context = p_cf_h.cloudflare_http_alert_context(self.http_event)
        # We have only 10 keeper keys in http alert context
        self.assertLessEqual(len(context), 10)
        self.assertIsNone(context.get("BotScore"))
        self.assertEqual("12.12.12.12", context.get("ClientIP"))


class TestAsanaHelpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "actor": {
                "actor_type": "user",
                "email": "user@domain.com",
                "gid": "11111111111111111111",
                "name": "Users Name",
            },
            "context": {
                "client_ip_address": "209.6.224.22",
                "context_type": "web",
                "user_agent": "AsanaDesktopOfficial darwin_arm64/1.12.0 Chrome/108.0.5359.62",
            },
            "created_at": "2023-02-08 19:00:14.355",
            "details": {},
            "event_category": "deletion",
            "event_type": "task_deleted",
            "gid": "1222222222222222",
            "p_event_time": "2023-02-08 19:00:14.355",
            "resource": {
                "gid": "133333333333333",
                "name": "Task Name Goes Here",
                "resource_subtype": "task",
                "resource_type": "task",
            },
        }

    def test_alert_context(self):
        returns = p_a_h.asana_alert_context(self.event)
        self.assertEqual(returns.get("actor", ""), "user@domain.com")
        self.assertEqual(returns.get("event_type", ""), "task_deleted")
        # Remove the user's email attribute
        self.event["actor"].pop("email")
        returns = p_a_h.asana_alert_context(self.event)
        self.assertEqual(returns.get("actor", ""), "<NO_ACTOR_EMAIL>")
        self.assertEqual(returns.get("resource_type", ""), "task")
        self.event["resource"] = {"resource_type": "story", "resource_subtype": "added_to_project"}
        returns = p_a_h.asana_alert_context(self.event)
        self.assertEqual(returns.get("resource_type", ""), "story__added_to_project")
        # resource with no resource subtype
        self.event["resource"] = {
            "email": "user@email.com",
            "gid": "1111111111111111",
            "name": "Users Name",
            "resource_type": "user",
        }
        returns = p_a_h.asana_alert_context(self.event)
        self.assertEqual(returns.get("resource_type", ""), "user")
        self.assertEqual(returns.get("resource_name", ""), "Users Name")
        self.assertEqual(returns.get("resource_gid", ""), "1111111111111111")

    def test_safe_ac_missing_entries(self):
        returns = p_a_h.asana_alert_context({})
        self.assertEqual(returns.get("actor"), "<NO_ACTOR>")
        self.assertEqual(returns.get("event_type"), "<NO_EVENT_TYPE>")
        self.assertEqual(returns.get("resource_type"), "<NO_RESOURCE_TYPE>")
        self.assertEqual(returns.get("resource_name"), "<NO_RESOURCE_NAME>")
        self.assertEqual(returns.get("resource_gid"), "<NO_RESOURCE_GID>")
        self.event["resource"]["resource_type"] = None
        returns = p_a_h.asana_alert_context(self.event)
        self.assertEqual(returns.get("resource_type"), "<NO_RESOURCE_TYPE>")

    def test_external_admin(self):
        event = {
            "actor": {"actor_type": "external_administrator"},
            "context": {"context_type": "api"},
            "created_at": "2023-02-13 18:41:02.759",
            "details": {},
            "event_category": "logins",
            "event_type": "user_logged_out",
            "gid": "1222222222222222",
            "resource": {
                "email": "user@email.com",
                "gid": "1201201201201201",
                "name": "User Name",
                "resource_type": "user",
            },
        }
        returns = p_a_h.asana_alert_context(event)
        self.assertEqual(returns.get("context"), "api")
        self.assertEqual(returns.get("actor"), "external_administrator")


class TestSnykHelpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "content": {"url": "/api/v1/user/me"},
            "created": "2022-12-27 16:50:46.959",
            "event": "api.access",
            "groupId": "8fffffff-1555-4444-b000-b55555555555",
            "orgId": "21111111-a222-4eee-8ddd-a99999999999",
            "userId": "05555555-3333-4ddd-8ccc-755555555555",
        }

    def test_alert_context(self):
        returns = p_snyk_h.snyk_alert_context(self.event)
        self.assertEqual(
            returns,
            {
                # pylint: disable=line-too-long
                "actor": "05555555-3333-4ddd-8ccc-755555555555",
                "action": "api.access",
                "groupId": "8fffffff-1555-4444-b000-b55555555555",
                "orgId": "21111111-a222-4eee-8ddd-a99999999999",
                "actor_link": "https://app.snyk.io/group/8fffffff-1555-4444-b000-b55555555555/manage/member/05555555-3333-4ddd-8ccc-755555555555",
            },
        )
        returns = p_snyk_h.snyk_alert_context({})
        self.assertEqual(
            returns,
            {
                "actor": "<NO_USERID>",
                "action": "<NO_EVENT>",
                "groupId": "<NO_GROUPID>",
                "orgId": "<NO_ORGID>",
            },
        )


class TestTinesHelpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "created_at": "2023-05-01 01:02:03",
            "id": 7206820,
            "operation_name": "Login",
            "request_ip": "12.12.12.12",
            "request_user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) UserAgent",
            "tenant_id": "1234",
            "user_email": "user@domain.com",
            "user_id": "17171",
            "user_name": "user at domain dot com",
        }

    def test_alert_context(self):
        returns = p_tines_h.tines_alert_context(self.event)
        self.assertEqual(
            returns,
            {
                "actor": "user@domain.com",
                "action": "Login",
                "tenant_id": "1234",
                "user_email": "user@domain.com",
                "user_id": "17171",
                "operation_name": "Login",
                "request_ip": "12.12.12.12",
            },
        )
        returns = p_tines_h.tines_alert_context({})
        self.assertEqual(
            returns,
            {
                "actor": "<NO_USEREMAIL>",
                "action": "<NO_OPERATION>",
                "tenant_id": "<NO_TENANTID>",
                "user_email": "<NO_USEREMAIL>",
                "user_id": "<NO_USERID>",
                "operation_name": "<NO_OPERATION>",
                "request_ip": "<NO_REQUESTIP>",
            },
        )


class TestAuth0Helpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "data": {
                "client_id": "1HXWWGKk1Zj3JF8GvMrnCSirccDs4qvr",
                "client_name": "",
                "date": "2023-05-15 17:41:31.451000000",
                "description": "Create a role",
                "details": {
                    "request": {
                        "auth": {
                            "credentials": {"jti": "949869e066205b5076e6df203fdd7b9b"},
                            "strategy": "jwt",
                            "user": {
                                "email": "user.name@yourcompany.io",
                                "name": "User Name",
                                "user_id": "google-oauth2|20839745023748560278",
                            },
                        },
                        "body": {"description": "custom_role", "name": "custom_role"},
                        "channel": "https://manage.auth0.com/",
                        "ip": "12.12.12.12",
                        "method": "post",
                        "path": "/api/v2/roles",
                        "query": {},
                    },
                    "response": {
                        "body": {
                            "description": "custom_role",
                            "id": "rol_AmvLkz7vhswmWJhJ",
                            "name": "custom_role",
                        },
                        "statusCode": 200,
                    },
                },
                "ip": "12.12.12.12",
                "log_id": "90020230515174135349782000000000000001223372037486042970",
                "type": "sapi",
                "user_id": "google-oauth2|105261262156475850461",
            },
            "log_id": "90020230515174135349782000000000000001223372037486042970",
        }

    def test_alert_context(self):
        returns = p_auth0_h.auth0_alert_context(self.event)
        auth0_config_event = p_auth0_h.is_auth0_config_event(self.event)
        self.assertEqual(
            returns.get("actor", ""),
            {
                "email": "user.name@yourcompany.io",
                "name": "User Name",
                "user_id": "google-oauth2|20839745023748560278",
            },
        )
        self.assertEqual(returns.get("action", ""), "Create a role")
        self.assertEqual(auth0_config_event, True)
        returns = p_auth0_h.auth0_alert_context({})
        auth0_config_event = p_auth0_h.is_auth0_config_event({})
        self.assertEqual(returns.get("actor", ""), "<NO_ACTOR_FOUND>")
        self.assertEqual(returns.get("action", ""), "<NO_ACTION_FOUND>")
        self.assertEqual(auth0_config_event, False)


@mock_dynamodb
class TestOssHelpers(unittest.TestCase):
    # pylint: disable=protected-access,assignment-from-no-return
    def setUp(self):
        os.environ["AWS_DEFAULT_REGION"] = "us-west-2"
        self._temp_dynamo = boto3.resource("dynamodb")
        self._temp_table = self._temp_dynamo.create_table(
            TableName="panther-kv-store",
            KeySchema=[
                {
                    "AttributeName": "key",
                    "KeyType": "HASH",
                }
            ],
            AttributeDefinitions=[
                {
                    "AttributeName": "key",
                    "AttributeType": "S",
                }
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            },
        )
        p_o_h._KV_TABLE = self._temp_table
        self.panther_key = p_o_h.reset_counter("panther")
        self.labs_key = p_o_h.reset_counter("labs")
        self.string_set_key = p_o_h.put_string_set("strs", ["a", "b"])

    def test_set_counter_ops(self):
        self.assertEqual(p_o_h.get_counter("panther"), 0)
        self.assertEqual(p_o_h.increment_counter("panther", 1), 1)
        self.assertEqual(p_o_h.increment_counter("panther", -2), -1)
        # something's weird when the val kwarg is zero. not sure it ever worked
        #    global_helpers/panther_oss_helpers.py", line 227, in increment_counter
        #    return response["Attributes"][_COUNT_COL].to_integral_value()
        # self.assertEqual(p_o_h.increment_counter("panther", 0), -1)
        self.assertEqual(p_o_h.increment_counter("panther", 11), 10)
        self.assertEqual(p_o_h.get_counter("panther"), 10)
        p_o_h.reset_counter("panther")
        self.assertEqual(p_o_h.get_counter("panther"), 0)
        self.assertEqual(p_o_h.get_counter("labs"), 0)
        self.assertEqual(p_o_h.get_counter("does-not-exist"), 0)
        # Set TTL
        exp_time = datetime.datetime.strptime("2023-04-01T00:00 +00:00", "%Y-%m-%dT%H:%M %z")
        p_o_h.set_key_expiration("panther", int(exp_time.timestamp()))
        panther_item = self._temp_table.get_item(
            Key={"key": "panther"}, ProjectionExpression=f"{p_o_h._COUNT_COL}, {p_o_h._TTL_COL}"
        )
        # Check TTL
        # moto may not be timezone aware when running dynamodb mock.. we ultimately want to confirm
        # that the expiresAt attribute is equal to exp_time.
        self.assertEqual(panther_item["Item"]["expiresAt"], exp_time.timestamp())

        ### TEST TYPE CONVERSIONS ON set_key_expiration
        # Set TTL as a string-with-decimals, expect back an int
        exp_time_2 = "1675238400.0000"
        p_o_h.set_key_expiration("panther", exp_time_2)
        panther_item = self._temp_table.get_item(
            Key={"key": "panther"}, ProjectionExpression=f"{p_o_h._COUNT_COL}, {p_o_h._TTL_COL}"
        )
        self.assertEqual(panther_item["Item"]["expiresAt"], 1675238400)

        # Set TTL as a string-without-decimals, expect back an int
        exp_time_2 = "1675238800"
        p_o_h.set_key_expiration("panther", exp_time_2)
        panther_item = self._temp_table.get_item(
            Key={"key": "panther"}, ProjectionExpression=f"{p_o_h._COUNT_COL}, {p_o_h._TTL_COL}"
        )
        self.assertEqual(panther_item["Item"]["expiresAt"], 1675238800)

        # Use datetime.timestamp() with millis, which gives back a float
        exp_time_2 = datetime.datetime.strptime(
            "2023-02-01T00:00.123 +00:00", "%Y-%m-%dT%H:%M.%f %z"
        )
        p_o_h.set_key_expiration("panther", int(exp_time_2.timestamp()))
        panther_item = self._temp_table.get_item(
            Key={"key": "panther"}, ProjectionExpression=f"{p_o_h._COUNT_COL}, {p_o_h._TTL_COL}"
        )
        self.assertEqual(panther_item["Item"]["expiresAt"], int(exp_time_2.timestamp()))

        # provide a timestamp that's seconds, not an actual epoch timestamp
        now = int(datetime.datetime.now().timestamp())

        # Set expiration time
        p_o_h.set_key_expiration("panther", "86400")
        panther_item = self._temp_table.get_item(
            Key={"key": "panther"}, ProjectionExpression=f"{p_o_h._COUNT_COL}, {p_o_h._TTL_COL}"
        )
        self.assertEqual(panther_item["Item"]["expiresAt"], now + 86400)

    def test_stringset_ops(self):
        self.assertEqual(p_o_h.add_to_string_set("strs2", ["b", "a"]), {"a", "b"})
        self.assertEqual(p_o_h.get_string_set("strs"), {"a", "b"})
        self.assertEqual(p_o_h.add_to_string_set("strs", ["c"]), {"a", "b", "c"})
        self.assertEqual(p_o_h.add_to_string_set("strs", set()), {"a", "b", "c"})
        self.assertEqual(p_o_h.add_to_string_set("strs", {"b", "c", "d"}), {"a", "b", "c", "d"})
        # tuple is allowed also
        self.assertEqual(p_o_h.add_to_string_set("strs", ("e", "a")), {"a", "b", "c", "d", "e"})
        # empty string is allowed
        self.assertEqual(p_o_h.add_to_string_set("strs", ""), {"a", "b", "c", "d", "e", ""})
        # list is allowed
        self.assertEqual(p_o_h.add_to_string_set("strs", ["g"]), {"a", "b", "c", "d", "e", "", "g"})
        # removal tests
        self.assertEqual(p_o_h.remove_from_string_set("strs", ""), {"a", "b", "c", "d", "e", "g"})
        # empty set test
        # NOTE: this failed unit testing for me. put_string_set with the empty
        # set as the only entry returns None
        # old unit test -> self.assertEqual(p_o_h.put_string_set("fake2", []), set())
        # new unit test vvv
        self.assertEqual(p_o_h.put_string_set("fake2", []), None)
        # Reset the stringset
        p_o_h.reset_string_set("strs")
        self.assertEqual(p_o_h.get_string_set("strs"), set())


class TestKmBetweenTwoIPInfoLocs(unittest.TestCase):
    def setUp(self):
        self.loc_nyc = {
            "city": "New York City",
            "country": "US",
            "lat": "40.71427",
            "lng": "-74.00597",
            "postal_code": "10004",
            "region": "New York",
            "region_code": "NY",
            "timezone": "America/New_York",
        }
        self.loc_sfo = {
            "city": "San Francisco",
            "country": "US",
            "lat": "37.77493",
            "lng": "-122.41942",
            "postal_code": "94102",
            "region": "California",
            "region_code": "CA",
            "timezone": "America/Los_Angeles",
        }
        self.loc_athens = {
            "city": "Athens",
            "country": "GR",
            "lat": "37.98376",
            "lng": "23.72784",
            "postal_code": "",
            "region": "Attica",
            "region_code": "I",
            "timezone": "Europe/Athens",
        }
        self.loc_aukland = {
            "city": "Auckland",
            "country": "NZ",
            "lat": "-36.84853",
            "lng": "174.76349",
            "postal_code": "1010",
            "region": "Auckland",
            "region_code": "AUK",
            "timezone": "Pacific/Auckland",
        }

    def test_distances(self):
        nyc_to_sfo = p_o_h.km_between_ipinfo_loc(self.loc_nyc, self.loc_sfo)
        nyc_to_athens = p_o_h.km_between_ipinfo_loc(self.loc_nyc, self.loc_athens)
        nyc_to_aukland = p_o_h.km_between_ipinfo_loc(self.loc_nyc, self.loc_aukland)
        aukland_to_nyc = p_o_h.km_between_ipinfo_loc(self.loc_aukland, self.loc_nyc)
        # I used https://www.nhc.noaa.gov/gccalc.shtml to get test comparison distances
        #
        # delta is set to 0.5% of total computed distanc from gccalc
        self.assertAlmostEqual(nyc_to_sfo, 4126, delta=20.63)
        self.assertAlmostEqual(nyc_to_athens, 7920, delta=39.6)
        self.assertAlmostEqual(nyc_to_aukland, 14184, delta=70.92)
        # and NYC to Aukland should be ~= Aukland to NYC
        self.assertEqual(nyc_to_aukland, aukland_to_nyc)


class TestNotionHelpers(unittest.TestCase):
    def setUp(self):
        self.event = {
            "id": "...",
            "timestamp": "2023-06-02T20:16:41.217Z",
            "workspace_id": "..",
            "actor": {
                "id": "..",
                "object": "user",
                "type": "person",
                "person": {"email": "user.name@yourcompany.io"},
            },
            "ip_address": "...",
            "platform": "mac-desktop",
            "type": "workspace.content_exported",
            "workspace.content_exported": {},
        }

    def test_alert_context(self):
        returns = p_notion_h.notion_alert_context(self.event)
        self.assertEqual(
            returns.get("actor", ""),
            {
                "id": "..",
                "object": "user",
                "type": "person",
                "person": {"email": "user.name@yourcompany.io"},
            },
        )
        self.assertEqual(returns.get("action", ""), "workspace.content_exported")
        returns = p_notion_h.notion_alert_context({})
        self.assertEqual(returns.get("actor", ""), "<NO_ACTOR_FOUND>")
        self.assertEqual(returns.get("action", ""), "<NO_ACTION_FOUND>")


if __name__ == "__main__":
    unittest.main()
