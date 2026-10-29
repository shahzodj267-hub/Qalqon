import pytest

from modules.detection.evaluator import EvaluationError, Matcher


def rule(detection):
    return {"title": "t", "detection": detection}


def test_endswith_is_case_insensitive_and_anchored():
    m = Matcher(rule({"s": {"Image|endswith": r"\cmd.exe"}, "condition": "s"}))
    assert m.matches({"Image": r"C:\Windows\System32\CMD.EXE"})
    assert not m.matches({"Image": r"C:\Windows\System32\cmd.exe.bak"})


def test_list_is_or():
    m = Matcher(rule({"s": {"CommandLine|contains": ["urlcache", "-split"]}, "condition": "s"}))
    assert m.matches({"CommandLine": "certutil -urlcache x"})
    assert m.matches({"CommandLine": "certutil -split x"})
    assert not m.matches({"CommandLine": "certutil -hashfile x"})


def test_contains_all_requires_every_value():
    m = Matcher(rule({"s": {"CommandLine|contains|all": ["-a", "-b"]}, "condition": "s"}))
    assert m.matches({"CommandLine": "x -a -b"})
    assert not m.matches({"CommandLine": "x -a"})


def test_wildcards():
    m = Matcher(rule({"s": {"Image": r"*\power?hell.exe"}, "condition": "s"}))
    assert m.matches({"Image": r"C:\x\powershell.exe"})
    assert not m.matches({"Image": r"C:\x\powershell.exe.txt"})


def test_regex():
    m = Matcher(rule({"s": {"CommandLine|re": r"-e(nc)?\s"}, "condition": "s"}))
    assert m.matches({"CommandLine": "ps -enc abc"})
    assert not m.matches({"CommandLine": "ps -Encoding utf8"})


def test_integer_event_id():
    m = Matcher(rule({"s": {"EventID": 4732}, "condition": "s"}))
    assert m.matches({"EventID": 4732})
    assert m.matches({"EventID": "4732"})
    assert not m.matches({"EventID": 4733})


def test_missing_field_never_matches():
    m = Matcher(rule({"s": {"TargetFileName|endswith": "a.exe"}, "condition": "s"}))
    assert not m.matches({"Image": "a.exe"})


def test_field_name_is_case_insensitive():
    m = Matcher(rule({"s": {"image|endswith": "a.exe"}, "condition": "s"}))
    assert m.matches({"Image": "a.exe"})


def test_keywords():
    m = Matcher(rule({"kw": ["mimikatz"], "condition": "kw"}))
    assert m.matches({"CommandLine": "run Mimikatz.exe now"})
    assert not m.matches({"CommandLine": "notepad"})


SEL = {"a": {"Image|endswith": "a.exe"}, "b": {"CommandLine|contains": "x"}, "filter_c": {"User": "SYSTEM"}}


def test_not_and_parentheses():
    m = Matcher(rule({**SEL, "condition": "(a or b) and not filter_c"}))
    assert m.matches({"Image": "a.exe", "User": "bob"})
    assert not m.matches({"Image": "a.exe", "User": "SYSTEM"})
    assert not m.matches({"Image": "z.exe", "CommandLine": "y", "User": "bob"})


def test_one_of_pattern_and_all_of_them():
    det = {"sel_a": {"Image|endswith": "a.exe"}, "sel_b": {"CommandLine|contains": "x"}}
    assert Matcher(rule({**det, "condition": "1 of sel_*"})).matches({"Image": "a.exe"})
    all_of = Matcher(rule({**det, "condition": "all of them"}))
    assert all_of.matches({"Image": "a.exe", "CommandLine": "x"})
    assert not all_of.matches({"Image": "a.exe"})


def test_selection_list_of_dicts_is_or():
    m = Matcher(rule({"s": [{"Image|endswith": "a.exe"}, {"CommandLine|contains": "x"}], "condition": "s"}))
    assert m.matches({"CommandLine": "x"})
    assert not m.matches({"CommandLine": "y"})


def test_fields_are_collected():
    m = Matcher(rule({"s": {"Image|endswith": "a", "EventID": 1}, "condition": "s"}))
    assert m.fields == {"Image", "EventID"}


@pytest.mark.parametrize(
    "detection",
    [
        {"s": {"Image|base64offset|contains": "x"}, "condition": "s"},
        {"s": {"Image": "x"}, "condition": "s | count() > 5"},
        {"s": {"Image": "x"}, "condition": "s", "timeframe": "5m"},
        {"s": {"Image": "x"}, "condition": "nope"},
        {"s": {"Image": "x"}, "condition": "(s"},
        {"s": {"Image": "x"}},
    ],
)
def test_unsupported_or_broken_raises(detection):
    with pytest.raises(EvaluationError):
        Matcher(rule(detection))
