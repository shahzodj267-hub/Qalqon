from typing import Optional

import typer

from core.ai import AIError, get_provider
from core.config import settings
from modules.detection import benchmark
from modules.detection.tester import LogFileError

bench_app = typer.Typer(help="AI modelni benchmark qilish (yashirin voqealar bilan)")


@bench_app.command()
def run(
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Model nomi (AI_PROVIDER ga qarab)"),
    only: Optional[str] = typer.Option(None, "--only", help="Faqat shu senariy (masalan ps_enc)"),
):
    """Barcha senariylarda qoida yozdiradi va yashirin voqealarda tekshiradi."""
    try:
        provider = get_provider()
        scenarios = benchmark.load_scenarios()
    except (AIError, LogFileError) as e:
        typer.secho(f"Xato: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if model:
        if provider.name == "ollama":
            settings.ollama_model = model
        else:
            settings.anthropic_model = model
    label = settings.ollama_model if provider.name == "ollama" else settings.anthropic_model

    if only:
        scenarios = [s for s in scenarios if s.name == only]
        if not scenarios:
            typer.secho(f"Senariy topilmadi: {only}", fg=typer.colors.RED)
            raise typer.Exit(1)

    typer.secho(f"Model: {provider.name} / {label}", bold=True)

    def show(r: benchmark.Result) -> None:
        if r.error:
            typer.secho(f"  {r.name:<12} XATO  {r.error}", fg=typer.colors.RED)
            return
        color = typer.colors.GREEN if r.passed else typer.colors.RED
        status = "PASS" if r.passed else "FAIL"
        typer.secho(
            f"  {r.name:<12} {status}  {r.attempts} urinish | ko'rinadigan: {r.visible} | yashirin: {r.hidden}",
            fg=color,
        )

    try:
        results = benchmark.run_all(provider, scenarios, on_done=show)
    except AIError as e:
        typer.secho(f"\nAI provayder xatosi, benchmark to'xtatildi: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
    passed = sum(r.passed for r in results)
    typer.secho(f"\nNatija: {passed}/{len(results)} senariy o'tdi", bold=True)
    if passed < len(results):
        raise typer.Exit(1)
