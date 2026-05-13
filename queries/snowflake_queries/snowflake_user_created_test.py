import os
import sys
import unittest

sys.path.append(os.path.dirname(__file__))
import snowflake_user_created as detection  # pylint: disable=C0413


def _event(query_text, user_name="admin"):
    return {"query_text": query_text, "user_name": user_name}


class TestSnowflakeUserCreatedTitle(unittest.TestCase):
    def test_standard_create_user(self):
        event = _event("CREATE USER testuser DEFAULT_ROLE = 'READONLY'")
        self.assertEqual(detection.title(event), "Snowflake user [testuser] created by [admin]")

    def test_if_not_exists_extracts_username(self):
        event = _event(
            "CREATE USER IF NOT EXISTS SERVICE_ACCOUNT DEFAULT_ROLE = SERVICE_ROLE TYPE='SERVICE'",
            user_name="PANTHER_ADMIN",
        )
        self.assertEqual(
            detection.title(event),
            "Snowflake user [SERVICE_ACCOUNT] created by [PANTHER_ADMIN]",
        )

    def test_case_insensitive(self):
        event = _event("create user if not exists lowercaseuser")
        self.assertEqual(
            detection.title(event), "Snowflake user [lowercaseuser] created by [admin]"
        )

    def test_unknown_user_on_unrecognized_query(self):
        event = _event("create")
        self.assertEqual(
            detection.title(event), "Snowflake user [<UNKNOWN_USER>] created by [admin]"
        )
