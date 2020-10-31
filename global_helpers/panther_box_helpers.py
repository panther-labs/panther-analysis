import base64
import json
import logging
from datetime import datetime, timedelta

import boto3

try:
    # boxsdk will only be available if `boxapi[jwt]` is
    #   in the pip env
    from boxsdk.exception import BoxAPIException
    from boxsdk import Client, JWTAuth
except ImportError as err:
    Client = None
    JWTAuth = None
    BoxAPIException = Exception

# Name for BOX secrets in AWS Secrets Manager
#   replace "secretid" with your secret id
BOX_API_ACCESS_NAME = 'panther-analyis/secretid'

# The following keys and associated values
#   should be stored in AWS Secrets Manager
BOX_CLIENT_ID = 'BOX_CLIENT_ID'
BOX_CLIENT_SECRET = 'BOX_CLIENT_SECRET'  # nosec
BOX_JWT_PRIVATE_KEY = 'BOX_JWT_PRIVATE_KEY'
BOX_JWT_PUB_KEY_ID = 'BOX_JWT_PUB_KEY_ID'
BOX_ENTERPRISE_ID = 'BOX_ENTERPRISE_ID'
BOX_JWT_KEY_PASSPHRASE = 'BOX_JWT_KEY_PASSPHRASE'  #nosec

# Used to cache client connetion to BOX API
BOX_CLIENT = None

# Cache credentials for 60 minutes at most
#  (the default box access token lifetime)
BOX_ACCESS_AGE = None
MAX_BOX_ACCESS_AGE = 60

# prevent INFO logs from going into the rules engine cloudtrail
logging.getLogger('boxsdk').setLevel(logging.CRITICAL)


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
    except BoxAPIException as err:
        raise BadBoxLookup('Exception looking up file info.') from err


def lookup_box_folder(user_id: str, folder_id: str) -> dict:
    try:
        client = get_box_client()
        user = client.user(user_id=user_id)
        folder = client.as_user(user).folder(folder_id=folder_id).get()
        return folder
    except BoxAPIException as err:
        raise BadBoxLookup('Exception looking up folder info.') from err


def get_box_client() -> Client:
    # pylint: disable=global-statement
    global BOX_ACCESS_AGE
    global BOX_CLIENT
    if not Client or not JWTAuth:
        raise Exception('Could not import necessary Box Library.')
    if BOX_CLIENT is not None and BOX_ACCESS_AGE is not None and datetime.now(
    ) - BOX_ACCESS_AGE < timedelta(minutes=MAX_BOX_ACCESS_AGE):
        return BOX_CLIENT
    response = boto3.client('secretsmanager').get_secret_value(
        SecretId=BOX_API_ACCESS_NAME)
    settings = build_jwt_settings(response)
    BOX_CLIENT = Client(JWTAuth.from_settings_dictionary(settings))
    BOX_ACCESS_AGE = datetime.now()
    return BOX_CLIENT


def build_jwt_settings(response: dict) -> dict:
    data = None
    if 'SecretString' in response:
        data = response['SecretString']
    else:
        data = base64.b64decode(response['SecretBinary'])
    # convert str from aws secrets mgr to json
    data = json.loads(data)
    # check that all necessary secrets are configured
    if not all(key in data for key in [
            BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_JWT_PRIVATE_KEY,
            BOX_JWT_PUB_KEY_ID, BOX_ENTERPRISE_ID, BOX_JWT_KEY_PASSPHRASE
    ]):
        raise BadSecretsLookup('Missing necessary secret(s): {}'.format([
            BOX_CLIENT_ID, BOX_CLIENT_SECRET, BOX_JWT_PRIVATE_KEY,
            BOX_JWT_PUB_KEY_ID, BOX_ENTERPRISE_ID, BOX_JWT_KEY_PASSPHRASE
        ]))
    # build box jwt settings from gathered secrets
    settings = {
        "boxAppSettings": {
            "clientID": data[BOX_CLIENT_ID],
            "clientSecret": data[BOX_CLIENT_SECRET],
            "appAuth": {
                "publicKeyID": data[BOX_JWT_PUB_KEY_ID],
                # handling of escaped newlines when dealing with
                #   secrets mgr -> str -> json.loads()
                "privateKey": data[BOX_JWT_PRIVATE_KEY].replace('\\n', '\n'),
                "passphrase": data[BOX_JWT_KEY_PASSPHRASE],
            },
        },
        "enterpriseID": data[BOX_ENTERPRISE_ID],
    }
    return settings
