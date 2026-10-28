import httpx

from core.config import settings
from modules.threat_intel.errors import IntelError

BASE_URL = "https://www.virustotal.com/api/v3"
ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
SUPPORTS = set(ENDPOINTS)


class VirusTotalError(IntelError):
    """VirusTotal bilan ishlashdagi xatolar."""


def _extra(kind: str, attrs: dict) -> str:
    if kind == "ip":
        return f"{attrs.get('country')} | {attrs.get('as_owner')}"
    if kind == "domain":
        return f"registrator: {attrs.get('registrar')} | reputatsiya: {attrs.get('reputation')}"
    return f"{attrs.get('meaningful_name')} | {attrs.get('type_description')}"


def check(value: str, kind: str) -> dict:
    if not settings.virustotal_api_key:
        raise VirusTotalError("VIRUSTOTAL_API_KEY .env faylida topilmadi")

    try:
        response = httpx.get(
            f"{BASE_URL}/{ENDPOINTS[kind]}/{value}",
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
        raise VirusTotalError("VirusTotal bazasida topilmadi")
    if response.status_code != 200:
        raise VirusTotalError(f"Kutilmagan javob: HTTP {response.status_code}")

    attrs = response.json()["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    return {
        "source": "virustotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "detail": f"zararli: {malicious}, shubhali: {suspicious} | {_extra(kind, attrs)}",
    }
