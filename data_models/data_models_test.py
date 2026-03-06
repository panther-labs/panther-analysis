import os
import sys
import unittest

from panther_analysis_tool.main import load_analysis, setup_data_models
from panther_core.enriched_event import PantherEvent

# pipenv run does the right thing, but IDE based debuggers may fail to import
#   so noting, we append this directory to sys.path
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__.replace("data_models", "global_helpers")))

specs, invalid_specs = load_analysis(os.path.dirname(__file__), [], [], [], True)
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


class TestAzureAKSDataModel(unittest.TestCase):
    data_model = log_type_to_data_model.get("Azure.MonitorActivity")

    def test_k8s_audit_fields(self):
        """Test that Azure AKS kube-audit logs parse Kubernetes fields correctly"""
        base_event = {
            "p_log_type": "Azure.MonitorActivity",
            "category": "kube-audit",
            "operationName": ("Microsoft.ContainerService/managedClusters/diagnosticLogs/Read"),
            "resourceId": (
                "/subscriptions/xxx/resourceGroups/rg/providers/"
                "Microsoft.ContainerService/managedClusters/cluster"
            ),
            "properties": {
                "log": (
                    '{"kind":"Event","apiVersion":"audit.k8s.io/v1",'
                    '"level":"RequestResponse","auditID":"abc-123",'
                    '"stage":"ResponseComplete",'
                    '"requestURI":"/apis/rbac.authorization.k8s.io/v1/namespaces/'
                    'default/rolebindings/test-binding","verb":"create",'
                    '"user":{"username":"admin@example.com",'
                    '"groups":["system:authenticated"]},'
                    '"sourceIPs":["10.0.0.1"],"userAgent":"kubectl/v1.28.0",'
                    '"objectRef":{"resource":"rolebindings","namespace":"default",'
                    '"name":"test-binding","apiGroup":"rbac.authorization.k8s.io",'
                    '"apiVersion":"v1"},"responseStatus":{"code":201},'
                    '"annotations":{"authorization.k8s.io/decision":"allow"}}'
                )
            },
        }

        event = PantherEvent(base_event, self.data_model)

        # Test unified Kubernetes fields
        self.assertEqual("create", event.udm("verb"))
        self.assertEqual("admin@example.com", event.udm("username"))
        self.assertEqual(["10.0.0.1"], event.udm("sourceIPs"))
        self.assertEqual("kubectl/v1.28.0", event.udm("userAgent"))
        self.assertEqual("rolebindings", event.udm("resource"))
        self.assertEqual("default", event.udm("namespace"))
        self.assertEqual("test-binding", event.udm("name"))
        self.assertEqual("rbac.authorization.k8s.io", event.udm("apiGroup"))
        self.assertEqual("v1", event.udm("apiVersion"))
        self.assertEqual(
            "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings/test-binding",
            event.udm("requestURI"),
        )
        self.assertIsNotNone(event.udm("annotations"))
        self.assertIsNotNone(event.udm("responseStatus"))

    def test_non_k8s_audit_log(self):
        """Test that non-kube-audit Azure logs return None for K8s fields"""
        non_k8s_event = {
            "p_log_type": "Azure.MonitorActivity",
            "category": "Administrative",
            "operationName": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE",
        }

        event = PantherEvent(non_k8s_event, self.data_model)

        # K8s fields should be None for non-kube-audit logs
        self.assertIsNone(event.udm("verb"))
        self.assertIsNone(event.udm("username"))
        self.assertIsNone(event.udm("resource"))
