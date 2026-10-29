from pathlib import Path

import pytest

from modules.detection import tester
from modules.detection.tester import LogFileError

ROOT = Path(__file__).parent.parent

# Modelning haqiqiy xato natijalari (TargetFileName va NewAccountName process/security voqealarida yo'q)
HALLUCINATED_OFFICE_RULE = r"""
title: Word or Excel Execution by cmd.exe or PowerShell.exe
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    Image|endswith: ['\cmd.exe', '\powershell.exe']
  selection_proc:
    TargetFileName|endswith: ['\winword.exe', '\excel.exe']
  condition: selection_img and selection_proc
level: medium
"""

BAD_ADMIN_RULE = """
title: New Local Administrator User Creation
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4720
    NewAccountName|endswith: '$'
  condition: selection
level: medium
"""


def run(rule_text, *logs, corpus=True):
    cases = []
    for log in logs:
        cases += tester.load_cases(ROOT / log)
    if corpus:
        cases += tester.load_cases(tester.DEFAULT_CORPUS)
    return tester.run_tests(rule_text, cases)


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_fixed_powershell_rule_passes():
    report = run(read("rules/examples/ps_encoded_fixed.yml"), "rules/tests/ps_encoded.yml")
    assert report.ok, [(r.case.note, r.matched) for r in report.results if not r.passed]
    assert report.hits == 3 and report.false_positives == 0


def test_original_ai_powershell_rule_has_problems():
    # AI yozgan eski qoida pwsh.exe ni o'tkazib yuboradi va -Encoding ni xato topadi
    report = run(read("rules/examples/ps_encoded.yml"), "rules/tests/ps_encoded.yml")
    assert not report.ok
    assert report.hits == 2
    assert report.false_positives == 1


def test_hallucinated_field_is_reported():
    report = run(HALLUCINATED_OFFICE_RULE, "rules/tests/office_shell.yml")
    assert not report.ok
    assert report.hits == 0
    assert report.missing_fields == ["TargetFileName"]


def test_bad_admin_rule_is_caught():
    report = run(BAD_ADMIN_RULE, "rules/tests/local_admin.yml")
    assert not report.ok
    assert report.hits == 0
    assert "NewAccountName" in report.missing_fields


def test_good_admin_rule_passes():
    report = run(read("rules/examples/local_admin_added.yml"), "rules/tests/local_admin.yml")
    assert report.ok
    assert report.hits == 2


def test_without_attack_events_rule_is_not_verified():
    report = run(read("rules/examples/ps_encoded_fixed.yml"))
    assert not report.verified
    assert not report.ok


def test_bad_log_file(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("events:\n  - expect: maybe\n    event: {a: 1}\n", encoding="utf-8")
    with pytest.raises(LogFileError):
        tester.load_cases(bad)
