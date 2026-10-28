from modules.threat_intel.errors import IntelError
import httpx

from core.config import settings

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBError(IntelError):
    """AbuseIPDB bilan ishlashdagi xatolar uchun."""


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    if not settings.abuseipdb_api_key:
        raise AbuseIPDBError("ABUSEIPDB_API_KEY .env faylida topilmadi")

    try:
        response = httpx.get(
            API_URL,
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        )
    except httpx.HTTPError as e:
        raise AbuseIPDBError(f"Tarmoq xatosi: {e}") from e

    if response.status_code == 401:
        raise AbuseIPDBError("API kalit noto'g'ri")
    if response.status_code == 429:
        raise AbuseIPDBError("Kunlik limit tugagan")
    if response.status_code != 200:
        raise AbuseIPDBError(f"Kutilmagan javob: HTTP {response.status_code}")

    data = response.json()["data"]
    return {
        "source": "abuseipdb",
        "ip": data["ipAddress"],
        "score": data["abuseConfidenceScore"],  # 0-100, yuqori = xavfliroq
        "reports": data["totalReports"],
        "users": data["numDistinctUsers"],
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "last_reported": data.get("lastReportedAt"),
    }
