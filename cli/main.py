import typer

from modules.threat_intel.aggregator import analyze

app = typer.Typer(help="Qalqon: kiberxavfsizlik platformasi")
from cli.rule import rule_app
app.add_typer(rule_app, name="rule")

KIND_NAMES = {"ip": "IP manzil", "domain": "Domen", "hash": "Fayl hash"}


@app.callback()
def main():
    """Qalqon CLI"""


@app.command()
def ioc(value: str):
    """IP, domen yoki fayl hash'ni bir necha manba bo'yicha tekshiradi."""
    try:
        result = analyze(value)
    except ValueError as e:
        typer.secho(str(e), fg=typer.colors.RED)
        raise typer.Exit(1)

    if result["score"] is None:
        typer.secho("Hech bir manba javob bermadi:", fg=typer.colors.RED)
        for e in result["errors"]:
            typer.echo(f"  - {e['source']}: {e['error']}")
        raise typer.Exit(1)

    score = result["score"]
    color = (
        typer.colors.GREEN if score < 25
        else typer.colors.YELLOW if score < 60
        else typer.colors.RED
    )

    typer.echo(f"{KIND_NAMES[result['kind']]}: {result['ioc']}")
    typer.secho(f"Xulosa: {result['verdict']} ({score}/100)", fg=color, bold=True)
    typer.echo("Manbalar:")
    for s in result["sources"]:
        typer.echo(f"  {s['source']:<11} xavf {s['risk']:>3}/100 | {s['detail']}")
        for note in s.get("notes", []):
            typer.echo(f"      - {note}")
    for e in result["errors"]:
        typer.secho(f"  ! {e['source']} o'tkazib yuborildi: {e['error']}", fg=typer.colors.YELLOW)


if __name__ == "__main__":
    app()
