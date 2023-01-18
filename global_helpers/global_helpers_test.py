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
import panther_cloudflare_helpers as p_cf_h  # pylint: disable=C0413
import panther_ipinfo_helpers as p_i_h  # pylint: disable=C0413
import panther_tor_helpers as p_tor_h  # pylint: disable=C0413


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


if __name__ == "__main__":
    unittest.main()
