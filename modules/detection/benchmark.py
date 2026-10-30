from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from core.ai import AIError, Provider
from modules.detection import generator, tester
from modules.detection.evaluator import EvaluationError
from modules.detection.tester import Case, LogFileError

BENCH_DIR = Path(__file__).resolve().parents[2] / "rules" / "bench"


@dataclass
class Scenario:
    name: str
    description: str
    visible: list[Case]
    hidden: list[Case]


@dataclass
class Result:
    name: str
    passed: bool
    attempts: int = 0
    visible: str = "-"
    hidden: str = "-"
    error: str = ""


def _cases(items, source: str) -> list[Case]:
    if not isinstance(items, list) or not items:
        raise LogFileError(f"{source}: voqealar ro'yxati bo'sh yoki yo'q")
    cases = []
    for i, item in enumerate(items, 1):
        expect = item.get("expect") if isinstance(item, dict) else None
        event = item.get("event") if isinstance(item, dict) else None
        if expect not in ("match", "no_match") or not isinstance(event, dict):
            raise LogFileError(f"{source}: {i}-yozuv noto'g'ri")
        cases.append(Case(expect == "match", str(item.get("note") or ""), event, source))
    return cases


def load_scenarios(directory: Path = BENCH_DIR) -> list[Scenario]:
    scenarios = []
    for path in sorted(Path(directory).glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            raise LogFileError(f"{path}: {e}") from e
        if not isinstance(data, dict) or not data.get("description"):
            raise LogFileError(f"{path}: 'description' kerak")
        scenarios.append(
            Scenario(
                path.stem,
                str(data["description"]),
                _cases(data.get("visible"), path.name),
                _cases(data.get("hidden"), path.name),
            )
        )
    if not scenarios:
        raise LogFileError(f"{directory}: senariy fayllari topilmadi")
    return scenarios


def _fmt(report) -> str:
    return f"hujum {report.hits}/{len(report.attacks)}, yolg'on signal {report.false_positives}/{len(report.benign)}"


def run_scenario(scenario: Scenario, provider: Provider, max_attempts: int = 3) -> Result:
    corpus = tester.load_cases(tester.DEFAULT_CORPUS)
    try:
        gen = generator.generate(
            scenario.description,
            provider=provider,
            max_attempts=max_attempts,
            cases=scenario.visible + corpus,
        )
        hidden = tester.run_tests(gen.yaml_text, scenario.hidden)
    except (generator.GenerationError, EvaluationError) as e:
        return Result(scenario.name, False, error=str(e).splitlines()[0][:400])

    visible_ok = bool(gen.report and gen.report.ok)
    return Result(
        scenario.name,
        visible_ok and hidden.ok,
        gen.attempts,
        _fmt(gen.report) if gen.report else "-",
        _fmt(hidden),
    )


def run_all(
    provider: Provider,
    scenarios: list[Scenario],
    on_done: Callable[[Result], None] | None = None,
) -> list[Result]:
    results = []
    for scenario in scenarios:
        result = run_scenario(scenario, provider)
        results.append(result)
        if on_done:
            on_done(result)
    return results
