import pytest

from aws_transit_gateway_audit.netutil import is_default_route, overlap, parse_cidr


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("10.20.0.0/16", "10.20.16.0/20", "10.20.16.0/20"),
        ("10.20.16.0/20", "10.20.0.0/16", "10.20.16.0/20"),
        ("10.10.0.0/16", "10.20.0.0/16", None),
        ("10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8"),
        ("0.0.0.0/0", "192.168.1.0/24", "192.168.1.0/24"),
        ("fd00::/8", "fd00:1::/32", "fd00:1::/32"),
        ("10.0.0.0/8", "fd00::/8", None),
        ("10.0.0.0/8", "not-a-cidr", None),
        ("", "10.0.0.0/8", None),
    ],
)
def test_overlap(left, right, expected):
    assert overlap(left, right) == expected


def test_parse_cidr_accepts_host_bits():
    assert str(parse_cidr("10.20.16.5/20")) == "10.20.16.0/20"


def test_parse_cidr_rejects_garbage():
    assert parse_cidr("10.20.16.0/99") is None
    assert parse_cidr(None) is None


def test_is_default_route():
    assert is_default_route("0.0.0.0/0")
    assert is_default_route("::/0")
    assert not is_default_route("10.0.0.0/8")
    assert not is_default_route("nonsense")
