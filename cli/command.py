import typer
import json
import os
import uvicorn
from cli.util import style_error, style_positive_response

cli_app = typer.Typer()
CONFIG_FILE = ".pgserve_config.json"

@cli_app.command()
def conf(key: str, cert: str, port: int = 443):
    """Save security configuration locally"""
    config = {
        "key": os.path.abspath(key),
        "cert": os.path.abspath(cert),
        "port": port
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
    typer.echo(style_positive_response(f"Config saved to {CONFIG_FILE}"))


@cli_app.command()
def start():
    """Start the server using saved config"""
    if not os.path.exists(CONFIG_FILE):
        typer.echo(style_error("Invalid config."))
        raise typer.Exit()

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    typer.echo(style_positive_response(f"Starting secure server on port {config['port']}..."))
    uvicorn.run("src.app:app", ssl_keyfile=config['key'], ssl_certfile=config['cert'])

