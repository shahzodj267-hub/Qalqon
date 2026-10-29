from pathlib import Path
from typing import Optional

import typer

from core.ai import AIError, get_provider
from modules.detection import converter, generator
from modules.detection.converter import RuleError

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
def generate(
    description: str,
    save: Optional[Path] = typer.Option(None, "--save", "-s", help="Sigma YAML'ni shu faylga saqlash"),
):
    """Oddiy tavsifdan AI yordamida Sigma qoidasi yaratadi va SPL/KQL ga o'giradi."""

    def on_retry(attempt: int, error: str) -> None:
        typer.secho(f"  urinish {attempt} muvaffaqiyatsiz: {error[:120]}", fg=typer.colors.YELLOW)

    try:
        provider = get_provider()
        typer.echo(f"AI provayder: {provider.name}. Qoida yozilmoqda...")
        result = generator.generate(description, provider=provider, on_retry=on_retry)
    except (AIError, generator.GenerationError) as e:
        typer.secho(f"Xato: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.secho(f"\nSintaksis OK ({result.attempts}-urinishda)", fg=typer.colors.GREEN, bold=True)
    typer.echo("\n--- SIGMA ---")
    typer.echo(result.yaml_text)
    _show(result.collection)
    for w in result.warnings:
        typer.secho(f"! {w}", fg=typer.colors.YELLOW)
    typer.secho(
        "\nDiqqat: qoida sintaksis jihatdan to'g'ri, lekin mantiqan to'g'riligini analitik tekshirishi kerak.",
        fg=typer.colors.YELLOW,
    )

    if save:
        save.write_text(result.yaml_text, encoding="utf-8")
        typer.echo(f"Saqlandi: {save}")
