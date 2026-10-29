import typer

from core.ai import AIError, get_provider

ai_app = typer.Typer(help="AI provayderni tekshirish")


@ai_app.command()
def test():
    """AI provayder ishlayotganini tekshiradi."""
    try:
        provider = get_provider()
        typer.echo(f"Provayder: {provider.name}")
        answer = provider.chat(
            "Sen qisqa javob beradigan yordamchisan.",
            [{"role": "user", "content": "Bitta jumla bilan: SIEM nima?"}],
        )
    except AIError as e:
        typer.secho(f"Xato: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
    typer.echo(answer)
