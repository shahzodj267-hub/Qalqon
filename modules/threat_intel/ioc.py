import ipaddress
import re

HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def refang(value: str) -> str:
    """evil[.]com -> evil.com (hisobotlarda zararli havolalar shunday yoziladi)."""
    return value.strip().replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")


def parse(value: str) -> tuple[str | None, str]:
    """(tur, tozalangan_qiymat) qaytaradi. Tur: 'ip', 'hash', 'domain' yoki None."""
    value = refang(value)
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    if HASH_RE.match(value):
        return "hash", value.lower()
    if DOMAIN_RE.match(value):
        return "domain", value.lower()
    return None, value
