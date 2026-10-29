from types import SimpleNamespace

import pytest

from modules.threat_intel import aggregator
from modules.threat_intel.aggregator import _risk, _verdict, analyze
from modules.threat_intel.errors import IntelError


def fake(supports, result=None, error=None):
    """Tarmoqsiz soxta manba moduli."""

    def check(value, kind):
        if error:
            raise error
        return dict(result)

    return SimpleNamespace(SUPPORTS=supports, check=check)


def use_sources(monkeypatch, **sources):
    monkeypatch.setattr(aggregator, "SOURCES", tuple(sources.items()))


ALL = {"ip", "domain", "hash"}


# --- risk va verdict ---

def test_risk_virustotal():
    assert _risk({"source": "virustotal", "malicious": 3, "suspicious": 2}) == 40


def test_risk_is_capped_at_100():
    assert _risk({"source": "virustotal", "malicious": 12, "suspicious": 1}) == 100
    assert _risk({"source": "otx", "pulses": 50}) == 100


def test_risk_abuseipdb_and_otx():
    assert _risk({"source": "abuseipdb", "score": 73}) == 73
    assert _risk({"source": "otx", "pulses": 5}) == 50


@pytest.mark.parametrize(
    "score, expected",
    [(0, "TOZA"), (24, "TOZA"), (25, "SHUBHALI"), (59, "SHUBHALI"), (60, "XAVFLI"), (100, "XAVFLI")],
)
def test_verdict_boundaries(score, expected):
    assert _verdict(score) == expected


# --- analyze ---

def test_all_clean(monkeypatch):
    use_sources(
        monkeypatch,
        abuseipdb=fake({"ip"}, {"source": "abuseipdb", "score": 0}),
        virustotal=fake(ALL, {"source": "virustotal", "malicious": 0, "suspicious": 0}),
        otx=fake(ALL, {"source": "otx", "pulses": 0}),
    )
    result = analyze("8.8.8.8")
    assert result["score"] == 0
    assert result["verdict"] == "TOZA"
    assert result["kind"] == "ip"


def test_confident_source_sets_floor(monkeypatch):
    # Bitta manba 100 desa ham, o'rtacha 40 bo'lardi; pol uni 60 ga ko'taradi.
    use_sources(
        monkeypatch,
        abuseipdb=fake({"ip"}, {"source": "abuseipdb", "score": 100}),
        virustotal=fake(ALL, {"source": "virustotal", "malicious": 0, "suspicious": 0}),
        otx=fake(ALL, {"source": "otx", "pulses": 0}),
    )
    result = analyze("1.2.3.4")
    assert result["score"] == 60
    assert result["verdict"] == "XAVFLI"


def test_failing_source_does_not_break_result(monkeypatch):
    use_sources(
        monkeypatch,
        abuseipdb=fake({"ip"}, {"source": "abuseipdb", "score": 50}),
        virustotal=fake(ALL, error=IntelError("limit tugagan")),
        otx=fake(ALL, {"source": "otx", "pulses": 0}),
    )
    result = analyze("1.2.3.4")
    # (0.4*50 + 0.2*0) / 0.6 = 33
    assert result["score"] == 33
    assert result["verdict"] == "SHUBHALI"
    assert result["errors"] == [{"source": "virustotal", "error": "limit tugagan"}]


def test_unsupported_kind_is_skipped_silently(monkeypatch):
    def must_not_be_called(value, kind):
        raise AssertionError("abuseipdb domen uchun chaqirilmasligi kerak")

    abuse = SimpleNamespace(SUPPORTS={"ip"}, check=must_not_be_called)
    use_sources(
        monkeypatch,
        abuseipdb=abuse,
        virustotal=fake(ALL, {"source": "virustotal", "malicious": 0, "suspicious": 0}),
    )
    result = analyze("google[.]com")
    assert result["kind"] == "domain"
    assert result["ioc"] == "google.com"
    assert result["errors"] == []
    assert [s["source"] for s in result["sources"]] == ["virustotal"]


def test_all_sources_fail(monkeypatch):
    use_sources(
        monkeypatch,
        virustotal=fake(ALL, error=IntelError("x")),
        otx=fake(ALL, error=IntelError("y")),
    )
    result = analyze("example.com")
    assert result["score"] is None
    assert result["verdict"] == "NOMA'LUM"
    assert len(result["errors"]) == 2


def test_invalid_input_raises():
    with pytest.raises(ValueError):
        analyze("salom")
