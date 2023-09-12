import base64
import json
import logging
import os
from datetime import datetime, timedelta

import boto3

try:
    # boxsdk will only be available if `boxapi[jwt]` is
    #   in the pip env
    from boxsdk import Client, JWTAuth
    from boxsdk.exception import BoxAPIException
except ImportError as err:
    Client = None
    JWTAuth = None
    BoxAPIException = Exception

# Name for BOX secrets in AWS Secrets Manager
BOX_API_ACCESS_NAME = "panther-analysis/box_api_access"

# The following keys and associated values
#   should be stored in AWS Secrets Manager
BOX_CLIENT_ID = "BOX_CLIENT_ID"
BOX_CLIENT_SECRET = "BOX_CLIENT_SECRET"  # nosec
BOX_JWT_PRIVATE_KEY = "BOX_JWT_PRIVATE_KEY"
BOX_JWT_PUB_KEY_ID = "BOX_JWT_PUB_KEY_ID"
BOX_ENTERPRISE_ID = "BOX_ENTERPRISE_ID"
BOX_JWT_KEY_PASSPHRASE = "BOX_JWT_KEY_PASSPHRASE"  # nosec

# Used to cache client connection to BOX API
BOX_CLIENT = None

# Cache credentials for 60 minutes at most
#  (the default box access token lifetime)
BOX_ACCESS_AGE = None
MAX_BOX_ACCESS_AGE = 60

# prevent INFO logs from going into the rules engine cloudtrail
logging.getLogger("boxsdk").setLevel(logging.CRITICAL)


class BadBoxLookup(Exception):
    """Error returned when a box item lookup fails."""


class BadSecretsLookup(Exception):
    """Error returned when an AWS Secrets Manager lookup fails."""


def is_box_sdk_enabled() -> bool:
    return Client and JWTAuth


def lookup_box_file(user_id: str, file_id: str) -> dict:
    try:
        client = get_box_client()
        user = client.user(user_id=user_id)
        file_info = client.as_user(user).file(file_id=file_id).get()
        return file_info
    except BoxAPIException as box_err:
        raise BadBoxLookup("Exception looking up file info.") from box_err


def lookup_box_folder(user_id: str, folder_id: str) -> dict:
    try:
        client = get_box_client()
        user = client.user(user_id=user_id)
        folder = client.as_user(user).folder(folder_id=folder_id).get()
        return folder
    except BoxAPIException as box_err:
        raise BadBoxLookup("Exception looking up folder info.") from box_err


def get_box_client() -> Client:
    # pylint: disable=global-statement
    global BOX_ACCESS_AGE
    global BOX_CLIENT

    fips_enabled = os.getenv("ENABLE_FIPS", "").lower() == "true"
    fips_suffix = "-fips." + os.getenv("AWS_REGION", "") + ".amazonaws.com"

    if not Client or not JWTAuth:
        raise Exception("Could not import necessary Box Library.")
    if (
        BOX_CLIENT is not None
        and BOX_ACCESS_AGE is not None
        and datetime.now() - BOX_ACCESS_AGE < timedelta(minutes=MAX_BOX_ACCESS_AGE)
    ):
        return BOX_CLIENT
    response = boto3.client(
        "secretsmanager",
        endpoint_url="https://secretsmanager" + fips_suffix if fips_enabled else None,
    ).get_secret_value(SecretId=BOX_API_ACCESS_NAME)
    settings = build_jwt_settings(response)
    BOX_CLIENT = Client(JWTAuth.from_settings_dictionary(settings))
    BOX_ACCESS_AGE = datetime.now()
    return BOX_CLIENT


def build_jwt_settings(response: dict) -> dict:
    data = None
    if "SecretString" in response:
        data = response.get("SecretString")
    else:
        data = base64.b64decode(response.get("SecretBinary", "{}"))
    # convert str from aws secrets mgr to json
    data = json.loads(data)
    # check that all necessary secrets are configured
    expected_keys = {
        BOX_CLIENT_ID,
        BOX_CLIENT_SECRET,
        BOX_JWT_PRIVATE_KEY,
        BOX_JWT_PUB_KEY_ID,
        BOX_ENTERPRISE_ID,
        BOX_JWT_KEY_PASSPHRASE,
    }
    missing_keys = expected_keys - set(data.keys())
    if len(missing_keys) != 0:
        raise BadSecretsLookup(f"Missing necessary secret(s): {missing_keys}")
    # build box jwt settings from gathered secrets
    settings = {
        "boxAppSettings": {
            "clientID": data.get(BOX_CLIENT_ID),
            "clientSecret": data.get(BOX_CLIENT_SECRET),
            "appAuth": {
                "publicKeyID": data.get(BOX_JWT_PUB_KEY_ID),
                # handling of escaped newlines when dealing with
                #   secrets mgr -> str -> json.loads()
                "privateKey": data.get(BOX_JWT_PRIVATE_KEY).replace("\\n", "\n"),
                "passphrase": data.get(BOX_JWT_KEY_PASSPHRASE),
            },
        },
        "enterpriseID": data[BOX_ENTERPRISE_ID],
    }
    return settings
