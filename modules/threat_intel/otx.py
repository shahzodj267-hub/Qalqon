import ipaddress

import httpx

from core.config import settings
from modules.threat_intel.errors import IntelError

API_URL = "https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general"
SUPPORTS = {"ip", "domain", "hash"}


class OTXError(IntelError):
    """AlienVault OTX bilan ishlashdagi xatolar."""


def _otx_kind(value: str, kind: str) -> str:
    if kind == "ip":
        return "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
    return {"domain": "domain", "hash": "file"}[kind]


def check(value: str, kind: str) -> dict:
    if not settings.otx_api_key:
        raise OTXError("OTX_API_KEY .env faylida topilmadi")

    try:
        response = httpx.get(
            API_URL.format(kind=_otx_kind(value, kind), value=value),
            headers={"X-OTX-API-KEY": settings.otx_api_key},
            timeout=15,
        )
    except httpx.HTTPError as e:
        raise OTXError(f"Tarmoq xatosi: {e}") from e

    if response.status_code in (401, 403):
        raise OTXError("API kalit noto'g'ri")
    if response.status_code == 404:
        raise OTXError("OTX bazasida topilmadi")
    if response.status_code == 429:
        raise OTXError("Limit tugagan")
    if response.status_code != 200:
        raise OTXError(f"Kutilmagan javob: HTTP {response.status_code}")

    data = response.json()
    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("count", 0)
    return {
        "source": "otx",
        "pulses": pulses,
        "detail": f"{pulses} ta tahdid hisoboti",
        "notes": [p.get("name") for p in pulse_info.get("pulses", [])[:3]],
    }
