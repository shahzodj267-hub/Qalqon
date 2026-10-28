from modules.threat_intel import abuseipdb, otx, virustotal
from modules.threat_intel.errors import IntelError

# Har manbaning umumiy ballga ta'siri. OTX shovqinliroq, shuning uchun vazni kam.
WEIGHTS = {"abuseipdb": 0.4, "virustotal": 0.4, "otx": 0.2}

SOURCES = (
    ("abuseipdb", abuseipdb),
    ("virustotal", virustotal),
    ("otx", otx),
)


def _risk(result: dict) -> int:
    """Har manba natijasini 0-100 xavf baliga o'giradi."""
    match result["source"]:
        case "abuseipdb":
            return result["score"]
        case "virustotal":
            return min(100, result["malicious"] * 10 + result["suspicious"] * 5)
        case "otx":
            return min(100, result["pulses"] * 10)
    return 0


def _verdict(score: int) -> str:
    if score < 25:
        return "TOZA"
    if score < 60:
        return "SHUBHALI"
    return "XAVFLI"


def analyze_ip(ip: str) -> dict:
    sources, errors = [], []

    for name, module in SOURCES:
        try:
            result = module.check_ip(ip)
        except IntelError as e:
            errors.append({"source": name, "error": str(e)})
            continue  # bitta manba yiqilsa, qolganlari ishlayveradi
        result["risk"] = _risk(result)
        sources.append(result)

    if not sources:
        return {"ip": ip, "score": None, "verdict": "NOMA'LUM", "sources": [], "errors": errors}

    # Javob bergan manbalar bo'yicha vaznli o'rtacha
    total_weight = sum(WEIGHTS[s["source"]] for s in sources)
    score = round(sum(WEIGHTS[s["source"]] * s["risk"] for s in sources) / total_weight)

    # Bitta manba juda aniq signal bersa, o'rtacha uni "suyultirib" yubormasin
    if max(s["risk"] for s in sources) >= 90:
        score = max(score, 60)

    return {"ip": ip, "score": score, "verdict": _verdict(score), "sources": sources, "errors": errors}
