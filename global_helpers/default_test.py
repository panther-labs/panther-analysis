#!/usr/bin/env python
# Unit tests for functions inside panther_default

import os
import sys
import unittest

sys.path.append(os.path.dirname(__file__))
import panther_aws_helpers as p_aws_h  # pylint: disable=C0413


class TestAWSKeyAccountId(unittest.TestCase):
    def test_aws_key_account_id(self):
        # Built at runtime so the source never contains a key-shaped literal.
        aws_key_id = "ASIA" + "BBBBBBBBBEXAMPLE"
        account_id = p_aws_h.extract_account_id(aws_key_id)
        self.assertEqual(account_id, "70936234050")

    def test_aws_role_account_id(self):
        aws_role_arn = "AROA" + "CCCCCCCCCEXAMPLE"
        account_id = p_aws_h.extract_account_id(aws_role_arn)
        self.assertEqual(account_id, "141872468100")
