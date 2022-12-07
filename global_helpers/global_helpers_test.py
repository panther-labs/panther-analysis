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


if __name__ == "__main__":
    unittest.main()
