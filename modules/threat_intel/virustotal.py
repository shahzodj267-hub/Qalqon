import httpx

from core.config import settings
from modules.threat_intel.errors import IntelError

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


class VirusTotalError(IntelError):
    """VirusTotal bilan ishlashdagi xatolar."""


def check_ip(ip: str) -> dict:
    if not settings.virustotal_api_key:
        raise VirusTotalError("VIRUSTOTAL_API_KEY .env faylida topilmadi")

    try:
        response = httpx.get(
            API_URL.format(ip=ip),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=15,
        )
    except httpx.HTTPError as e:
        raise VirusTotalError(f"Tarmoq xatosi: {e}") from e

    if response.status_code == 401:
        raise VirusTotalError("API kalit noto'g'ri")
    if response.status_code == 429:
        raise VirusTotalError("Limit tugagan (bepul: daqiqasiga 4 so'rov)")
    if response.status_code == 404:
        raise VirusTotalError("IP VirusTotal bazasida topilmadi")
    if response.status_code != 200:
        raise VirusTotalError(f"Kutilmagan javob: HTTP {response.status_code}")

    attrs = response.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    return {
        "source": "virustotal",
        "malicious": stats.get("malicious", 0),    # nechta antivirus "zararli" dedi
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attrs.get("country"),
        "owner": attrs.get("as_owner"),
    }
