from pathlib import Path
from typing import Optional

import typer

from core.ai import AIError, get_provider
from modules.detection import converter, generator, tester
from modules.detection.converter import RuleError
from modules.detection.evaluator import EvaluationError

rule_app = typer.Typer(help="Sigma qoidalari bilan ishlash")


def _show(collection) -> None:
    for rule in collection.rules:
        typer.secho(f"Qoida: {rule.title} [{rule.level}]", bold=True)
    typer.echo(f"MITRE ATT&CK: {', '.join(converter.attack_techniques(collection)) or 'yo`q'}")

    for target in converter.BACKENDS:
        typer.echo(f"\n--- {target.upper()} ---")
        try:
            for query in converter.convert(collection, target):
                typer.echo(query)
        except RuleError as e:
            typer.secho(f"Tarjima bo'lmadi: {e}", fg=typer.colors.YELLOW)


def _describe(case: tester.Case) -> str:
    return case.note or str(case.event)[:90]


def _print_report(report: tester.Report) -> None:
    typer.secho(f"\n--- SINOV: {report.title} ---", bold=True)
    for r in report.results:
        if r.case.expect_match:
            if r.matched:
                typer.secho(f"  ✓ hujum topildi:         {_describe(r.case)}", fg=typer.colors.GREEN)
            else:
                typer.secho(f"  ✗ hujum o'tkazib yuborildi: {_describe(r.case)}", fg=typer.colors.RED)
        elif r.matched:
            typer.secho(f"  ✗ yolg'on signal:        {_describe(r.case)}", fg=typer.colors.RED)

    typer.echo(
        f"\nHujum: {report.hits}/{len(report.attacks)} topildi | "
        f"Yolg'on signal: {report.false_positives}/{len(report.benign)}"
    )
    for field in report.missing_fields:
        typer.secho(
            f"! '{field}' maydoni hech bir namunaviy logda yo'q: qoida bu maydonga tayansa, hech qachon ishlamaydi",
            fg=typer.colors.YELLOW,
        )

    if not report.verified:
        typer.secho("Hujum voqealari berilmagan: qoidaning topishi sinalmadi.", fg=typer.colors.YELLOW)
    elif report.ok:
        typer.secho(
            "Sinovdan o'tdi (faqat shu namunaviy voqealar bo'yicha; haqiqiy muhitda baribir tekshiring).",
            fg=typer.colors.GREEN,
            bold=True,
        )
    else:
        typer.secho("Sinovdan o'tmadi.", fg=typer.colors.RED, bold=True)


def _run_tests(yaml_text: str, logs: list[Path], use_corpus: bool = True) -> bool:
    try:
        cases = []
        for path in logs:
            cases += tester.load_cases(path)
        if use_corpus:
            cases += tester.load_cases(tester.DEFAULT_CORPUS)
        report = tester.run_tests(yaml_text, cases)
    except (tester.LogFileError, EvaluationError) as e:
        typer.secho(f"Sinov bajarilmadi: {e}", fg=typer.colors.RED)
        return False
    _print_report(report)
    return report.ok


@rule_app.command()
def convert(path: Path):
    """Sigma YAML faylini tekshiradi va Splunk SPL / KQL ga o'giradi."""
    if not path.is_file():
        typer.secho(f"Fayl topilmadi: {path}", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        collection = converter.load(path.read_text(encoding="utf-8"))
    except RuleError as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(1)
    _show(collection)


@rule_app.command()
def test(
    path: Path,
    logs: list[Path] = typer.Argument(..., help="Namunaviy voqealar fayli (yoki bir nechta)"),
    no_corpus: bool = typer.Option(False, "--no-corpus", help="Umumiy zararsiz voqealar to'plamini qo'shmaslik"),
):
    """Qoidani namunaviy voqealarda sinaydi: hujumni topadimi, zararsizni o'tkazib yuboradimi."""
    if not path.is_file():
        typer.secho(f"Fayl topilmadi: {path}", fg=typer.colors.RED)
        raise typer.Exit(1)
    if not _run_tests(path.read_text(encoding="utf-8"), logs, use_corpus=not no_corpus):
        raise typer.Exit(1)


@rule_app.command()
def generate(
    description: str,
    save: Optional[Path] = typer.Option(None, "--save", "-s", help="Sigma YAML'ni shu faylga saqlash"),
    logs: Optional[list[Path]] = typer.Option(None, "--logs", "-l", help="Qoidani shu voqealar faylida sinash"),
):
    """Oddiy tavsifdan AI yordamida Sigma qoidasi yaratadi, loglarda sinaydi va SPL/KQL ga o'giradi."""
    cases = None
    if logs:
        try:
            cases = []
            for path in logs:
                cases += tester.load_cases(path)
            cases += tester.load_cases(tester.DEFAULT_CORPUS)
        except tester.LogFileError as e:
            typer.secho(f"Sinov fayli xato: {e}", fg=typer.colors.RED)
            raise typer.Exit(1)

    def on_retry(attempt: int, error: str) -> None:
        typer.secho(f"  urinish {attempt} muvaffaqiyatsiz: {error[:120]}", fg=typer.colors.YELLOW)

    try:
        provider = get_provider()
        typer.echo(f"AI provayder: {provider.name}. Qoida yozilmoqda...")
        result = generator.generate(description, provider=provider, on_retry=on_retry, cases=cases)
    except (AIError, generator.GenerationError) as e:
        typer.secho(f"Xato: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.secho(f"\nSintaksis OK ({result.attempts}-urinishda)", fg=typer.colors.GREEN, bold=True)
    typer.echo("\n--- SIGMA ---")
    typer.echo(result.yaml_text)
    _show(result.collection)
    for w in result.warnings:
        typer.secho(f"! {w}", fg=typer.colors.YELLOW)

    if save:
        save.write_text(result.yaml_text, encoding="utf-8")
        typer.echo(f"Saqlandi: {save}")

    if result.report:
        _print_report(result.report)
        if not result.report.ok:
            raise typer.Exit(1)
    else:
        typer.secho(
            "\nDiqqat: sintaksis tekshirildi, mantiq emas. Mantiqiy sinov uchun: --logs rules/tests/<fayl>.yml",
            fg=typer.colors.YELLOW,
        )
