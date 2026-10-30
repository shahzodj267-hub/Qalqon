from pathlib import Path

from modules.detection import benchmark

ROOT = Path(__file__).parent.parent
FENCE = "`" * 3

MEMORIZED = """title: Memorized
description: x
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: 'JABhAD0AMQA='
  condition: sel
falsepositives:
  - x
level: medium
"""


class FakeProvider:
    name = "fake"

    def __init__(self, replies):
        self.replies = list(replies)

    def chat(self, system, messages, temperature=0.2):
        return self.replies.pop(0)


def _fenced(text):
    return FENCE + "yaml\n" + text + FENCE


def _scenario(name):
    return next(s for s in benchmark.load_scenarios() if s.name == name)


def test_scenarios_load():
    assert [s.name for s in benchmark.load_scenarios()] == ["certutil", "local_admin", "office", "ps_enc"]


def test_good_rule_passes_hidden_events():
    rule = (ROOT / "rules/examples/ps_encoded_fixed.yml").read_text(encoding="utf-8")
    result = benchmark.run_scenario(_scenario("ps_enc"), FakeProvider([_fenced(rule)]))
    assert result.passed, result


def test_memorized_rule_fails_hidden_events():
    result = benchmark.run_scenario(_scenario("ps_enc"), FakeProvider([_fenced(MEMORIZED)]))
    assert not result.passed
    assert "hujum 0/2" in result.hidden
