from panther_base_helpers import deep_get

APPROVED_TENANCIES = {"default"}


def policy(resource):
    return deep_get(resource, "Placement", "Tenancy") in APPROVED_TENANCIES
