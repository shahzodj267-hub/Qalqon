import ipaddress

import typer

from modules.threat_intel.aggregator import analyze_ip

app = typer.Typer(help="Qalqon: kiberxavfsizlik platformasi")


@app.callback()
def main():
    """Qalqon CLI"""


def _print_source(s: dict) -> None:
    match s["source"]:
        case "abuseipdb":
            typer.echo(
                f"  AbuseIPDB   xavf {s['risk']:>3}/100 | {s['reports']} hisobot "
                f"({s['users']} foydalanuvchi) | {s['country']} | {s['isp']}"
            )
        case "virustotal":
            typer.echo(
                f"  VirusTotal  xavf {s['risk']:>3}/100 | zararli: {s['malicious']}, "
                f"shubhali: {s['suspicious']} | {s['country']} | {s['owner']}"
            )
        case "otx":
            typer.echo(f"  OTX         xavf {s['risk']:>3}/100 | {s['pulses']} ta tahdid hisoboti | {s['country']}")
            for name in s["pulse_names"]:
                typer.echo(f"                 - {name}")


@app.command()
def ioc(ip: str):
    """IP manzilni bir necha manba bo'yicha tekshiradi."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        typer.secho(f"'{ip}' to'g'ri IP manzil emas", fg=typer.colors.RED)
        raise typer.Exit(1)

    result = analyze_ip(ip)

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

    typer.echo(f"IP: {result['ip']}")
    typer.secho(f"Xulosa: {result['verdict']} ({score}/100)", fg=color, bold=True)
    typer.echo("Manbalar:")
    for s in result["sources"]:
        _print_source(s)
    for e in result["errors"]:
        typer.secho(f"  ! {e['source']} o'tkazib yuborildi: {e['error']}", fg=typer.colors.YELLOW)


if __name__ == "__main__":
    app()
