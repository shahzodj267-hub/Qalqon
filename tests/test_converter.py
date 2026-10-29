from pathlib import Path

import pytest

from modules.detection import converter
from modules.detection.converter import RuleError

EXAMPLE = Path(__file__).parent.parent / "rules" / "examples" / "certutil_download.yml"


@pytest.fixture
def collection():
    return converter.load(EXAMPLE.read_text(encoding="utf-8"))


def test_load_example(collection):
    assert len(collection.rules) == 1
    assert collection.rules[0].title == "Certutil Download Activity"


def test_attack_techniques(collection):
    # "attack.command-and-control" texnika emas (taktika), faqat T1105 olinishi kerak
    assert converter.attack_techniques(collection) == ["T1105"]


def test_convert_splunk(collection):
    queries = converter.convert(collection, "splunk")
    assert len(queries) == 1
    assert "certutil.exe" in queries[0].lower()


def test_convert_kql(collection):
    queries = converter.convert(collection, "kql")
    assert len(queries) == 1
    assert "certutil.exe" in queries[0].lower()


def test_broken_yaml_raises():
    with pytest.raises(RuleError):
        converter.load("title: [yopilmagan")


def test_missing_detection_raises():
    with pytest.raises(RuleError):
        converter.load("title: Bo'sh qoida\nlogsource:\n  category: process_creation\n")
