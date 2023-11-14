#!/usr/bin/env python
# Unit tests for functions inside panther_default

import os
import sys
import unittest

sys.path.append(os.path.dirname(__file__))
import panther_default as p_d  # pylint: disable=C0413


class TestAWSKeyAccountID(unittest.TestCase):
    def test_aws_key_account_id(self):
        aws_key_id = "ASIAY34FZKBOKMUTVV7A"
        account_id = p_d.aws_key_account_id(aws_key_id)
        self.assertEqual(account_id, "609629065308")
