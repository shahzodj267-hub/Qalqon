import ipaddress

import httpx

from core.config import settings
from modules.threat_intel.errors import IntelError

API_URL = "https://otx.alienvault.com/api/v1/indicators/{kind}/{ip}/general"


class OTXError(IntelError):
    """AlienVault OTX bilan ishlashdagi xatolar."""


def check_ip(ip: str) -> dict:
    if not settings.otx_api_key:
        raise OTXError("OTX_API_KEY .env faylida topilmadi")

    kind = "IPv6" if ipaddress.ip_address(ip).version == 6 else "IPv4"

    try:
        response = httpx.get(
            API_URL.format(kind=kind, ip=ip),
            headers={"X-OTX-API-KEY": settings.otx_api_key},
            timeout=15,
        )
    except httpx.HTTPError as e:
        raise OTXError(f"Tarmoq xatosi: {e}") from e

    if response.status_code in (401, 403):
        raise OTXError("API kalit noto'g'ri")
    if response.status_code == 429:
        raise OTXError("Limit tugagan")
    if response.status_code != 200:
        raise OTXError(f"Kutilmagan javob: HTTP {response.status_code}")

    data = response.json()
    pulse_info = data.get("pulse_info", {})
    return {
        "source": "otx",
        "pulses": pulse_info.get("count", 0),  # shu IP tilga olingan tahdid hisobotlari soni
        "pulse_names": [p.get("name") for p in pulse_info.get("pulses", [])[:3]],
        "country": data.get("country_name"),
        "asn": data.get("asn"),
    }
