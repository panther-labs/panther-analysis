#!/usr/bin/env python
# Unit tests for panther_base_helpers.py

import os
import sys
import unittest

## NOTE: WE DO NOT WANT TO IMPORT panther_analysis_tool into any detection
#  we need the types from panther_analysis_tool for unit testing sometimes, though
from panther_analysis_tool.immutable import ImmutableCaseInsensitiveDict, ImmutableList

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))

import panther_base_helpers as p_b_h  # pylint: disable=C0413


class TestBoxParseAdditionalDetails(unittest.TestCase):
    def setUp(self):
        self.initial_dict = {"t": 10, "a": [{"b": 1, "c": 2}], "d": {"e": {"f": True}}}
        self.immutable_dict = ImmutableCaseInsensitiveDict(self.initial_dict)
        self.initial_list = ["1", 2, True, False]
        self.immutable_list = ImmutableList(self.initial_list)

    def test_additional_details_string(self):
        event = {"additional_details": '{"string_encoded_json": true}'}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(returns.get("string_encoded_json", None), True)

    def test_additional_details_immutabledict(self):
        event = {"additional_details": self.immutable_dict}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(returns.get("t", 0), 10)

    def test_additional_details_immutablelist(self):
        event = {"additional_details": self.immutable_list}
        returns = p_b_h.box_parse_additional_details(event)
        self.assertEqual(returns[2], True)


if __name__ == "__main__":
    unittest.main()
