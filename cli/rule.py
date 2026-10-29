from pathlib import Path

import typer

from modules.detection import converter
from modules.detection.converter import RuleError

rule_app = typer.Typer(help="Sigma qoidalari bilan ishlash")


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
