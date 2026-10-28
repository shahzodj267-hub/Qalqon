import ipaddress

import typer

from modules.threat_intel.abuseipdb import AbuseIPDBError, check_ip

app = typer.Typer(help="Qalqon: kiberxavfsizlik platformasi")


@app.callback()
def main():
    """Qalqon CLI"""


@app.command()
def ioc(ip: str):
    """IP manzilni tekshiradi."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        typer.secho(f"'{ip}' to'g'ri IP manzil emas", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        result = check_ip(ip)
    except AbuseIPDBError as e:
        typer.secho(f"Xato: {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    score = result["score"]
    color = (
        typer.colors.GREEN if score < 25
        else typer.colors.YELLOW if score < 75
        else typer.colors.RED
    )
    typer.echo(f"IP:        {result['ip']}")
    typer.secho(f"Xavf bali: {score}/100", fg=color, bold=True)
    typer.echo(f"Hisobotlar: {result['reports']} ta ({result['users']} ta alohida foydalanuvchidan)")
    typer.echo(f"Davlat:    {result['country']}")
    typer.echo(f"Provayder: {result['isp']}")
    typer.echo(f"Turi:      {result['usage_type']}")
    typer.echo(f"Oxirgi:    {result['last_reported']}")


if __name__ == "__main__":
    app()
