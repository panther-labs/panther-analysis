import pytest

from panther_greynoise_helpers import (
    GreyNoiseAdvanced,
    GreyNoiseBasic,
    PantherIncorrectIPAddressMethodException
)

from panther_core.immutable import ImmutableList, ImmutableCaseInsensitiveDict



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
