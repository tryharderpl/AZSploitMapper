"""
Command-line interface for AZSploitMapper.

Provides these commands:
  - scan:              Run a security scan against an Azure subscription
  - serve:             Start the web dashboard server
  - generate-api-key:  Create a new API key for authentication
  - list-api-keys:     Show all API keys and their status
  - revoke-api-key:    Revoke an API key by its prefix

Usage:
  python -m azsploitmapper scan --subscription-id YOUR_SUB_ID
  python -m azsploitmapper serve --port 8443
  python -m azsploitmapper generate-api-key --name "admin"
"""

import os
import ssl
from pathlib import Path
import click
import uvicorn
from rich.console import Console
from rich.table import Table

from azsploitmapper import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="AZSploitMapper")
def main():
    """AZSploitMapper - Azure Attack Path Visualizer"""
    pass


@main.command()
@click.option(
    "--subscription-id", required=True, help="Azure subscription ID to scan"
)
@click.option(
    "--resource-group", default="", help="Limit scan to a specific resource group"
)
@click.option(
    "--cli-only", is_flag=True, help="Print results to terminal without starting web server"
)
@click.option(
    "--port", default=8443, help="Web dashboard port (default: 8443)"
)
def scan(subscription_id: str, resource_group: str, cli_only: bool, port: int):
    """
    Run a security scan on an Azure subscription.

    Discovers resources, detects misconfigurations, builds the attack graph,
    and finds attack paths. Results are shown in the terminal and optionally
    in the web dashboard.
    """
    from azsploitmapper.scanner.orchestrator import ScanOrchestrator
    from azsploitmapper.graph.builder import GraphBuilder
    from azsploitmapper.graph.attack_paths import AttackPathFinder
    from azsploitmapper.graph.risk_scorer import RiskScorer

    console.print(f"\n[bold blue]AZSploitMapper[/bold blue] v{__version__}\n")

    # Phase 1: Discover resources
    orchestrator = ScanOrchestrator(
        subscription_id=subscription_id,
        resource_group=resource_group,
    )
    scan_results = orchestrator.run_scan()
    resources = scan_results["resources"]

    # Phase 2: Build the attack graph
    console.print("\n  Building attack graph...")
    builder = GraphBuilder()
    graph = builder.build(resources)
    nodes = builder.get_nodes()
    console.print(
        f"  Graph: [cyan]{graph.number_of_nodes()}[/cyan] nodes, "
        f"[cyan]{graph.number_of_edges()}[/cyan] edges"
    )

    # Phase 3: Find attack paths
    console.print("  Searching for attack paths...")
    finder = AttackPathFinder(graph)
    paths = finder.find_all_paths()

    # Phase 4: Score paths
    scorer = RiskScorer()
    paths = scorer.score_paths(paths, nodes)

    # Print attack path summary
    summary = finder.get_path_summary(paths)
    _print_path_summary(summary)

    # Print each attack path
    if paths:
        _print_attack_paths(paths)

    if cli_only:
        console.print("\n[dim]CLI-only mode, web server not started.[/dim]\n")
        return

    # Start web server with results pre-loaded
    console.print(f"\n  Starting web dashboard at [link]https://localhost:{port}[/link]")
    console.print("  Press Ctrl+C to stop.\n")

    from azsploitmapper.api.app import create_app
    import uuid

    app = create_app()
    scan_id = str(uuid.uuid4())
    # Get findings from the scan output
    findings = scan_results.get("findings", [])

    # Attach findings to graph nodes for risk scoring
    for finding in findings:
        node = nodes.get(finding.resource_id)
        if node:
            node.findings.append(finding.to_dict())

    findings_dicts = [f.to_dict() for f in findings]

    scan_store = {
        "scan_id": scan_id,
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "resources": resources,
        "resource_counts": scan_results["resource_counts"],
        "graph": graph,
        "nodes": nodes,
        "paths": paths,
        "findings": findings_dicts,
        "cytoscape_json": builder.to_cytoscape_json(),
        "path_summary": summary,
    }
    app.state.scan_results[scan_id] = scan_store

    # Persist to SQLite so the scan survives restarts
    from azsploitmapper.db.database import save_scan
    save_scan(app.state.db_engine, scan_id, scan_store)

    _run_server(app, port)


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8443, help="Port to listen on (default: 8443)")
def serve(host: str, port: int):
    """Start the web dashboard server (without running a scan)."""
    from azsploitmapper.api.app import create_app

    console.print(f"\n[bold blue]AZSploitMapper[/bold blue] dashboard")
    console.print(f"  Listening on [link]https://{host}:{port}[/link]")
    console.print("  Use POST /api/scan to trigger a scan.\n")

    app = create_app()
    _run_server(app, port, host)


@main.command("generate-api-key")
@click.option("--name", required=True, help="Descriptive name for the key (e.g. 'admin', 'ci-pipeline')")
@click.option("--expires-days", default=90, help="Days until key expires (default: 90)")
def generate_api_key_cmd(name: str, expires_days: int):
    """
    Generate a new API key for authenticating to the web dashboard.

    The full key is shown ONLY ONCE. Store it securely immediately.
    You can also set it as the AZSPLOITMAPPER_API_KEY environment variable.
    """
    from azsploitmapper.auth.api_keys import generate_api_key

    result = generate_api_key(name=name, expires_days=expires_days)

    console.print("\n[bold green]API Key Generated Successfully[/bold green]\n")
    console.print(f"  Name:       {result['name']}")
    console.print(f"  Prefix:     {result['prefix']}")
    console.print(f"  Expires:    {result['expires_at']}")
    console.print()
    console.print("[bold yellow]IMPORTANT: Copy this key NOW. It will NOT be shown again.[/bold yellow]")
    console.print()
    console.print(f"  [bold white]{result['key']}[/bold white]")
    console.print()
    console.print("Usage options:")
    console.print("  1. Set as environment variable:")
    console.print(f"     export AZSPLOITMAPPER_API_KEY={result['key']}")
    console.print("  2. Use in HTTP requests:")
    console.print(f"     curl -H 'Authorization: Api-Key {result['key']}' https://localhost:8443/api/health")
    console.print()


@main.command("list-api-keys")
def list_api_keys_cmd():
    """List all API keys with their status."""
    from azsploitmapper.auth.api_keys import list_api_keys

    keys = list_api_keys()
    if not keys:
        console.print("\n  No API keys found. Generate one with:")
        console.print("  python -m azsploitmapper generate-api-key --name admin\n")
        return

    table = Table(title="API Keys")
    table.add_column("Name", style="cyan")
    table.add_column("Prefix", style="dim")
    table.add_column("Created", style="green")
    table.add_column("Expires", style="yellow")
    table.add_column("Last Used", style="blue")
    table.add_column("Status", justify="center")

    for key in keys:
        status = "[red]REVOKED[/red]" if key["revoked"] else "[green]ACTIVE[/green]"
        table.add_row(
            key["name"],
            key["prefix"],
            key["created_at"][:19],
            key["expires_at"][:19],
            (key["last_used"] or "never")[:19],
            status,
        )

    console.print(table)


@main.command("revoke-api-key")
@click.option("--prefix", required=True, help="Key prefix to revoke (e.g. azm_abc12345)")
def revoke_api_key_cmd(prefix: str):
    """Revoke an API key by its prefix. Revoked keys cannot authenticate."""
    from azsploitmapper.auth.api_keys import revoke_api_key

    if revoke_api_key(prefix):
        console.print(f"\n  [green]Key {prefix} revoked successfully.[/green]\n")
    else:
        console.print(f"\n  [red]Key with prefix {prefix} not found.[/red]\n")


def _run_server(app, port: int, host: str = "0.0.0.0"):
    """
    Start uvicorn with TLS if certificates are available.

    Looks for TLS certificates at the paths specified by TLS_CERT_PATH
    and TLS_KEY_PATH environment variables, or in the certs/ directory.
    Falls back to HTTP with a warning if no certs are found.
    """
    # Resolve cert paths: try env var first, then project-relative default
    project_root = Path(__file__).resolve().parent.parent
    default_cert = str(project_root / "certs" / "cert.pem")
    default_key = str(project_root / "certs" / "key.pem")

    cert_path = os.getenv("TLS_CERT_PATH", "")
    key_path = os.getenv("TLS_KEY_PATH", "")

    # If env var paths don't exist (e.g. Docker paths on local machine), fall back to defaults
    if not cert_path or not os.path.exists(cert_path):
        cert_path = default_cert
    if not key_path or not os.path.exists(key_path):
        key_path = default_key

    ssl_kwargs = {}
    if os.path.exists(cert_path) and os.path.exists(key_path):
        console.print(f"  [green]TLS enabled[/green] (cert: {cert_path})")
        ssl_kwargs["ssl_certfile"] = cert_path
        ssl_kwargs["ssl_keyfile"] = key_path
    else:
        console.print(
            "  [bold yellow]WARNING: No TLS certificates found.[/bold yellow]"
        )
        console.print(
            "  Running without TLS is insecure. Generate self-signed certs:"
        )
        console.print(
            "  openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem "
            "-out certs/cert.pem -days 365 -nodes -subj '/CN=localhost'"
        )
        console.print()

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="warning",
        # Limit request body size to 1MB to prevent DoS
        h11_max_incomplete_event_size=1_048_576,
        **ssl_kwargs,
    )


def _print_path_summary(summary: dict):
    """Print attack path statistics to the terminal."""
    console.print("\n[bold]Attack Path Summary:[/bold]")
    console.print(f"  Total paths found:    [cyan]{summary['total_paths']}[/cyan]")
    console.print(f"  Critical paths:       [red]{summary['critical_paths']}[/red]")
    console.print(f"  Unique targets:       [yellow]{summary['targets_reached']}[/yellow]")
    if summary["total_paths"] > 0:
        console.print(f"  Avg path length:      {summary['avg_path_length']} hops")
        console.print(f"  Shortest path:        {summary['shortest_path']} hops")


def _print_attack_paths(paths: list):
    """Print each attack path in a formatted table."""
    table = Table(title="\nAttack Paths", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Risk", justify="center", width=6)
    table.add_column("Path", min_width=40)
    table.add_column("Hops", justify="center", width=5)

    for i, path in enumerate(paths, 1):
        score = path.risk_score
        if score >= 7.0:
            risk_style = "[bold red]"
        elif score >= 4.0:
            risk_style = "[yellow]"
        else:
            risk_style = "[green]"

        table.add_row(
            str(i),
            f"{risk_style}{score:.1f}[/]",
            path.description,
            str(len(path.nodes) - 1),
        )

    console.print(table)
