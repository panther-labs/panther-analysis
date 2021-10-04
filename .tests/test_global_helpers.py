import os
import sys
import unittest

GLOBAL_HELPERS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'global_helpers'))

if GLOBAL_HELPERS_PATH not in sys.path:
    sys.path.append(GLOBAL_HELPERS_PATH)

import panther_base_helpers


class TestDeepGetLegacy(unittest.TestCase):
    def test_key_path_exists(self):
        self.assertEqual(
            panther_base_helpers.deep_get_legacy({"session": {"key": 1}}, "session", "key"),
            1
        )

    def test_no_keys(self):
        self.assertDictEqual(
            panther_base_helpers.deep_get_legacy({"session": {"key": 1}}),
            {"session": {"key": 1}}
        )

    def test_no_keys_not_a_mapping(self):
        self.assertListEqual(
            panther_base_helpers.deep_get_legacy([1]),
            [1]
        )

    def test_key_path_does_not_exist(self):
        self.assertIsNone(
            panther_base_helpers.deep_get_legacy({"session": {"key": 1}}, "session", "different_key")
        )

    def test_default(self):
        self.assertEqual(
            panther_base_helpers.deep_get_legacy({"session": {"key": 1}}, "session", "different_key", default=8),
            8
        )
        self.assertEqual(
            panther_base_helpers.deep_get_legacy({"session": {"key": 1}}, "session", "key", default=8),
            1
        )

    def test_non_mapping_type(self):
        self.assertEqual(
            panther_base_helpers.deep_get_legacy([1], "session", "different_key", default=8),
            8
        )


class TestDeepGet(unittest.TestCase):
    def test_key_path_exists(self):
        self.assertEqual(
            panther_base_helpers.deep_get({"session": {"key": 1}}, "session", "key"),
            1
        )

    def test_no_keys(self):
        self.assertIsNone(
            panther_base_helpers.deep_get({"session": {"key": 1}})
        )

    def test_no_keys_not_a_mapping(self):
        self.assertIsNone(
            panther_base_helpers.deep_get([1])
        )

    def test_key_path_does_not_exist(self):
        self.assertIsNone(
            panther_base_helpers.deep_get({"session": {"key": 1}}, "session", "different_key")
        )

    def test_default(self):
        self.assertEqual(
            panther_base_helpers.deep_get({"session": {"key": 1}}, "session", "different_key", default=8),
            8
        )
        self.assertEqual(
            panther_base_helpers.deep_get({"session": {"key": 1}}, "session", "key", default=8),
            1
        )

    def test_non_mapping_type(self):
        default_value = object()
        self.assertIs(
            panther_base_helpers.deep_get([1], "session", "different_key", default=default_value),
            default_value
        )
