import pytest

from modules.detection import generator
from modules.detection.generator import GenerationError, extract_yaml, generate

FENCE = "`" * 3

GOOD_YAML = r"""title: Certutil Download Activity
id: not-a-uuid
description: Detects certutil used to download files
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\certutil.exe'
  selection_cli:
    CommandLine|contains:
      - 'urlcache'
      - '-split'
  condition: selection_img and selection_cli
falsepositives:
  - Rare administrative use
level: medium
"""
GOOD_REPLY = "Mana qoida:\n" + FENCE + "yaml\n" + GOOD_YAML + FENCE + "\nOmad!"
BAD_REPLY = FENCE + "yaml\ntitle: Faqat sarlavha\n" + FENCE


class FakeProvider:
    name = "fake"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def chat(self, system, messages):
        self.calls.append(list(messages))
        return self.replies.pop(0)


def test_extract_fenced():
    assert extract_yaml("matn\n" + FENCE + "yaml\na: 1\n" + FENCE + "\nmatn") == "a: 1"


def test_extract_plain():
    assert extract_yaml("  a: 1  ") == "a: 1"


def test_first_try_success_and_fields_overridden():
    result = generate("certutil yuklash", provider=FakeProvider([GOOD_REPLY]))
    assert result.attempts == 1
    assert "not-a-uuid" not in result.yaml_text
    assert "author: Qalqon" in result.yaml_text
    assert result.warnings == []


def test_retry_after_invalid_rule():
    provider = FakeProvider([BAD_REPLY, GOOD_REPLY])
    retries = []
    result = generate("x", provider=provider, on_retry=lambda n, e: retries.append(n))
    assert result.attempts == 2
    assert retries == [1]
    # ikkinchi so'rovda: tavsif + AI javobi + xato haqida xabar
    assert len(provider.calls[1]) == 3
    assert "failed validation" in provider.calls[1][2]["content"]


def test_non_yaml_reply_triggers_retry():
    result = generate("x", provider=FakeProvider(["Kechirasiz, yordam bera olmayman.", GOOD_REPLY]))
    assert result.attempts == 2


def test_gives_up_after_max_attempts():
    with pytest.raises(GenerationError):
        generate("x", provider=FakeProvider([BAD_REPLY] * 3), max_attempts=3)


def test_prompt_forbids_secrets_fields():
    assert "Do NOT write id" in generator.SYSTEM_PROMPT


def test_deprecated_technique_triggers_retry():
    pytest.importorskip("sigma.data.mitre_attack")
    old = GOOD_REPLY.replace("attack.t1105", "attack.t1086")
    result = generate("x", provider=FakeProvider([old, GOOD_REPLY]))
    assert result.attempts == 2


def test_invented_windows_category_triggers_retry():
    bad = GOOD_REPLY.replace("category: process_creation", "category: account_creation")
    result = generate("x", provider=FakeProvider([bad, GOOD_REPLY]))
    assert result.attempts == 2


def test_yaml_or_mistake_gets_hint():
    broken = "title: x\ndetection:\n  sel:\n    Image|endswith: '\\a.exe' or Image|endswith: '\\b.exe'\n"
    provider = FakeProvider([broken, GOOD_REPLY])
    result = generate("x", provider=provider)
    assert result.attempts == 2
    assert "inside a value" in provider.calls[1][2]["content"]
