#!/usr/bin/env python
# Unit tests for functions inside panther_default

import os
import sys
import unittest

sys.path.append(os.path.dirname(__file__))
import panther_aws_helpers as p_aws_h  # pylint: disable=C0413


class TestAWSKeyAccountId(unittest.TestCase):
    def test_aws_key_account_id(self):
        aws_key_id = "ASIAXXXXXXXXXXXXXXXX"
        account_id = p_aws_h.extract_account_id(aws_key_id)
        self.assertEqual(account_id, "532021755375")

    def test_aws_role_account_id(self):
        aws_role_arn = "AROASXLWWOM4TZXHTA6HN"
        account_id = p_aws_h.extract_account_id(aws_role_arn)
        self.assertEqual(account_id, "187616883513")
