import os
import sys
import unittest

from panther_analysis_tool.main import load_analysis, setup_data_models
from panther_core.enriched_event import PantherEvent

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__.replace("data_models", "global_helpers")))

specs, invalid_specs = load_analysis(os.path.dirname(__file__), [], [], [])
log_type_to_data_model, invalid_data_models = setup_data_models(specs.data_models)


class TestAWSCloudTrailDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("AWS.CloudTrail")

    def test_get_actor_user(self):
        base_event = {
            "p_log_type": "AWS.CloudTrail",
            "userIdentity": {
                "type": "user_type",
                "principalId": "AIDAJ45Q7YFFAREXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/Alice",
                "accountId": "Root",
                "accessKeyId": "",
                "userName": "Root,IAMUser,Directory,Unknown,SAMLUser,WebIdentityUser",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "principalId": "AROAIDPPEZS35WEXAMPLE",
                        "arn": "arn:aws:iam::123456789012:role/RoleToBeAssumed",
                        "accountId": "123456789012",
                        "userName": "AssumedRole,Role,FederatedUser",
                    },
                },
            },
            "additionalEventData": {"CredentialType": "PASSWORD", "UserName": "IdentityCenterUser"},
            "sourceIdentity": "AWSService,AWSAccount",
        }

        aws_service_event = PantherEvent(
            {
                "p_log_type": "AWS.CloudTrail",
                "eventType": "AwsServiceEvent",
                "userIdentity": {"invokedBy": "AwsServiceEvent"},
            },
            self.data_model,
        )

        user_types = (
            "Root",
            "IAMUser",
            "Directory",
            "Unknown",
            "SAMLUser",
            "WebIdentityUser",
            "AssumedRole",
            "Role",
            "FederatedUser",
            "IdentityCenterUser",
            "AWSService",
            "AWSAccount",
        )

        for user_type in user_types:
            event = PantherEvent(
                base_event | {"userIdentity": {"type": user_type}}, self.data_model
            )
            self.assertTrue(user_type in event.udm("actor_user"))

        self.assertEqual("AwsServiceEvent", aws_service_event.udm("actor_user"))
