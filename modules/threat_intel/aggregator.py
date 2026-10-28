from modules.threat_intel import abuseipdb, ioc, otx, virustotal
from modules.threat_intel.errors import IntelError

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


def analyze(raw_value: str) -> dict:
    kind, value = ioc.parse(raw_value)
    if kind is None:
        raise ValueError(f"'{raw_value}' IP, domen yoki hash emas")

    sources, errors = [], []
    for name, module in SOURCES:
        if kind not in module.SUPPORTS:
            continue  # bu manba shu turni bilmaydi, jim o'tkazamiz
        try:
            result = module.check(value, kind)
        except IntelError as e:
            errors.append({"source": name, "error": str(e)})
            continue
        result["risk"] = _risk(result)
        sources.append(result)

    base = {"ioc": value, "kind": kind, "sources": sources, "errors": errors}
    if not sources:
        return {**base, "score": None, "verdict": "NOMA'LUM"}

    total_weight = sum(WEIGHTS[s["source"]] for s in sources)
    score = round(sum(WEIGHTS[s["source"]] * s["risk"] for s in sources) / total_weight)
    if max(s["risk"] for s in sources) >= 90:
        score = max(score, 60)

    return {**base, "score": score, "verdict": _verdict(score)}
