from dataclasses import dataclass
from pathlib import Path

import yaml

from modules.detection.evaluator import EvaluationError, Matcher

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "rules" / "samples" / "benign_process_creation.yml"


class LogFileError(Exception):
    """Log (voqealar) fayli noto'g'ri."""


@dataclass
class Case:
    expect_match: bool
    note: str
    event: dict
    source: str = ""


@dataclass
class CaseResult:
    case: Case
    matched: bool

    @property
    def passed(self) -> bool:
        return self.matched == self.case.expect_match


@dataclass
class Report:
    title: str
    results: list[CaseResult]
    missing_fields: list[str]

    @property
    def attacks(self) -> list[CaseResult]:
        return [r for r in self.results if r.case.expect_match]

    @property
    def benign(self) -> list[CaseResult]:
        return [r for r in self.results if not r.case.expect_match]

    @property
    def hits(self) -> int:
        return sum(r.matched for r in self.attacks)

    @property
    def false_positives(self) -> int:
        return sum(r.matched for r in self.benign)

    @property
    def verified(self) -> bool:
        """Hujum voqealari bo'lmasa, qoidaning topishi sinalmagan bo'ladi."""
        return bool(self.attacks)

    @property
    def ok(self) -> bool:
        return self.verified and all(r.passed for r in self.results)


def load_cases(path: Path) -> list[Case]:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise LogFileError(f"{path}: {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise LogFileError(f"{path}: 'events:' ro'yxati kerak")

    cases = []
    for i, item in enumerate(data["events"], 1):
        expect = item.get("expect") if isinstance(item, dict) else None
        event = item.get("event") if isinstance(item, dict) else None
        if expect not in ("match", "no_match") or not isinstance(event, dict):
            raise LogFileError(f"{path}: {i}-yozuv noto'g'ri (expect: match yoki no_match, va event: {{...}} kerak)")
        cases.append(Case(expect == "match", str(item.get("note") or ""), event, Path(path).name))
    return cases


def run_tests(yaml_text: str, cases: list[Case]) -> Report:
    try:
        rule = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise EvaluationError(f"Qoida YAML'i noto'g'ri: {e}") from e
    if not isinstance(rule, dict):
        raise EvaluationError("Qoida YAML lug'at emas")

    matcher = Matcher(rule)
    seen = {str(k).lower() for case in cases for k in case.event}
    missing = sorted(f for f in matcher.fields if f.lower() not in seen)
    results = [CaseResult(case, matcher.matches(case.event)) for case in cases]
    return Report(str(rule.get("title", "?")), results, missing)
