import pytest

from modules.threat_intel.ioc import parse, refang

MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.mark.parametrize("value", ["8.8.8.8", "185.220.101.4", "2001:db8::1"])
def test_ip(value):
    assert parse(value) == ("ip", value)


@pytest.mark.parametrize("value", [MD5, SHA1, SHA256])
def test_hash(value):
    assert parse(value) == ("hash", value)


def test_hash_is_lowercased():
    assert parse(SHA256.upper()) == ("hash", SHA256)


@pytest.mark.parametrize("value", ["google.com", "sub.example.co.uk", "XN--80ASEHDB.com"])
def test_domain(value):
    assert parse(value) == ("domain", value.lower())


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("google[.]com", ("domain", "google.com")),
        ("evil(.)example(.)com", ("domain", "evil.example.com")),
        ("8[.]8[.]8[.]8", ("ip", "8.8.8.8")),
        ("  google.com  ", ("domain", "google.com")),
    ],
)
def test_defang_and_whitespace(raw, expected):
    assert parse(raw) == expected


@pytest.mark.parametrize(
    "value",
    ["salom", "", "999.1.1.1", "http://evil.com", "evil.com/path", MD5 + "0", "a b.com"],
)
def test_invalid(value):
    kind, _ = parse(value)
    assert kind is None


def test_refang():
    assert refang("a[.]b[dot]c") == "a.b.c"
