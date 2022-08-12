import pytest

from panther_greynoise_helpers import (
    GreyNoiseAdvanced,
    GreyNoiseBasic,
    PantherIncorrectIPAddressMethodException
)

from panther_core.immutable import ImmutableList, ImmutableCaseInsensitiveDict

# These are unit tests associated with the ip_addresses list handling change.
# This functionality was also tested in the panther console, by creating a dectations
# rule and creating data that looks like what is below. I ran two pieces of code in the
# Rule Function, and created four test cases.
#
    # ip = noise.ip_address('p_any_ip_addresses')
    # ctx = noise.context('p_any_ip_addresses')
    # if isinstance(ip, str) and ip == "0.1.2.3.4" and 'IP' in ctx.keys():
    #     return True
    #
    # ips = noise.ip_addresses('p_any_ip_addresses')
    # ctx = noise.context('p_any_ip_addresses')
    # if isinstance(ips, ImmutableList) and 'IPs' in ctx.keys():
    #     return True
#
# I expected that when the ip_addresses passes which returns a list, the string test
# should return the correct error message and visa versa.

test_data_basic_list = [(
    {
        "ip_address": "2.2.2.2",
        "request_user":
        "test","request_time":
        "time","p_enrichment": {
            "greynoise_noise_basic": {
                "p_any_ip_addresses": [
                    "8.8.8.8",
                    "1.1.1.1",
                    "localhost",
                    "2.3.4.5",
                ],
            }
        }
    }
)]

test_data_basic_str = [(
    {
        "ip_address": "2.2.2.2",
        "request_user": "test",
        "request_time": "time",
        "p_enrichment": {
            "greynoise_noise_basic": {
                "p_any_ip_addresses": {
                    "actor": "unknown", "ip": "8.8.8.8","classification": "unknown"
                },
            }
        }
    }
)]

test_data_advanced_list = [(
    {
        "ip_address": "2.2.2.2",
        "request_user": "test",
        "request_time": "time",
        "p_enrichment": {
            "greynoise_noise_advanced": {
                "p_any_ip_addresses": [
                    {"actor": "unknown", "ip": "8.8.8.8","classification": "unknown"},
                ],
            }
        }
    }
)]
test_data_advanced_str = [(
    {
        "ip_address": "2.2.2.2",
        "request_user": "test",
        "request_time": "time",
        "p_enrichment": {
            "greynoise_noise_advanced": {
                "p_any_ip_addresses": {
                    "actor": "unknown", "ip": "8.8.8.8","classification": "unknown"
                },
            }
        }
    }
)]

def cast_test_data(data):
    return ImmutableCaseInsensitiveDict(data)

@pytest.mark.parametrize("data", test_data_basic_list)
def test_greynoise_basic_addresses(data):
    data = cast_test_data(data)
    noise = GreyNoiseBasic(data)
    try:
        noise.ip_address("p_any_ip_addresses")
    except PantherIncorrectIPAddressMethodException:
        pass
    ip_list = noise.ip_addresses("p_any_ip_addresses")
    assert isinstance(ip_list, ImmutableList)

    ctx = noise.context('p_any_ip_addresses')
    assert 'IPs' in ctx.keys()

@pytest.mark.parametrize("data", test_data_basic_str)
def test_greynoise_basic_address(data):
    data = cast_test_data(data)
    noise = GreyNoiseBasic(data)
    try:
        noise.ip_addresses("p_any_ip_addresses")
    except PantherIncorrectIPAddressMethodException:
        pass

    ip_str = noise.ip_address("p_any_ip_addresses")
    assert isinstance(ip_str, str)

    ctx = noise.context('p_any_ip_addresses')
    assert 'IP' in ctx.keys()

@pytest.mark.parametrize("data", test_data_advanced_list)
def test_greynoise_advanced_addresses(data):
    data = cast_test_data(data)
    noise = GreyNoiseAdvanced(data)
    try:
        noise.ip_address("p_any_ip_addresses")
    except PantherIncorrectIPAddressMethodException:
        pass

    ip_list = noise.ip_addresses("p_any_ip_addresses")
    assert isinstance(ip_list, ImmutableList)

    ctx = noise.context('p_any_ip_addresses')
    assert 'IPs' in ctx.keys()

@pytest.mark.parametrize("data", test_data_advanced_str)
def test_greynoise_advanced_address(data):
    data = cast_test_data(data)
    noise = GreyNoiseAdvanced(data)
    try:
        noise.ip_addresses("p_any_ip_addresses")
    except PantherIncorrectIPAddressMethodException:
        pass

    ip_str = noise.ip_address("p_any_ip_addresses")
    assert isinstance(ip_str, str)

    ctx = noise.context('p_any_ip_addresses')
    assert 'IP' in ctx.keys()
