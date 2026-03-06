"""
Scan orchestrator - coordinates the full scan lifecycle.

The orchestrator is the central coordinator that:
1. Creates Azure SDK clients for authentication
2. Runs all enabled resource collectors in sequence
3. Feeds discovered resources into the rule engine
4. Passes everything to the graph builder for attack path analysis
"""

from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from azsploitmapper.scanner.auth import AzureClients
from azsploitmapper.scanner.collectors.compute import ComputeCollector
from azsploitmapper.scanner.collectors.network import NetworkCollector
from azsploitmapper.scanner.collectors.storage import StorageCollector
from azsploitmapper.scanner.collectors.identity import IdentityCollector
from azsploitmapper.scanner.collectors.keyvault import KeyVaultCollector
from azsploitmapper.scanner.rules.engine import RuleEngine
from azsploitmapper.scanner.collectors.secrets import SecretScanner

console = Console()

# Maps collector names (from config) to their classes
COLLECTOR_REGISTRY = {
    "compute": ComputeCollector,
    "network": NetworkCollector,
    "storage": StorageCollector,
    "identity": IdentityCollector,
    "keyvault": KeyVaultCollector,
}


class ScanOrchestrator:
    """
    Coordinates a full security scan of an Azure subscription.

    Usage:
        orchestrator = ScanOrchestrator(subscription_id="xxx")
        results = orchestrator.run_scan()
    """

    def __init__(
        self,
        subscription_id: str,
        resource_group: str = "",
        enabled_collectors: list[str] | None = None,
        rules_dir: str = "config/rules",
        enable_secret_scanning: bool = True,
    ):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.enabled_collectors = enabled_collectors or list(COLLECTOR_REGISTRY.keys())
        self.rules_dir = rules_dir
        self.enable_secret_scanning = enable_secret_scanning

        # Azure SDK client factory (lazy initialization)
        self.clients = AzureClients(subscription_id)

        # Rule engine for misconfiguration detection
        self.rule_engine = RuleEngine(rules_dir=rules_dir)

        # Secret scanner for detecting exposed credentials
        self.secret_scanner = SecretScanner()

    def run_scan(self) -> dict:
        """
        Execute the full scan pipeline and return all results.

        Returns a dict with:
        - resources: list of all discovered Azure resources
        - resource_counts: dict mapping resource type to count
        """
        console.print(
            f"\n[bold blue]AZSploitMapper[/bold blue] scanning subscription "
            f"[cyan]{self.subscription_id}[/cyan]"
        )
        if self.resource_group:
            console.print(f"  Scope: resource group [cyan]{self.resource_group}[/cyan]")
        else:
            console.print("  Scope: [cyan]entire subscription[/cyan]")

        # Phase 1: Discover all Azure resources
        all_resources = self._run_collectors()

        # Phase 2: Evaluate rules against discovered resources
        findings = self._run_rules(all_resources)

        # Phase 3: Scan resources for exposed secrets / credentials
        if self.enable_secret_scanning:
            secret_findings = self._run_secret_scan(all_resources)
            findings.extend(secret_findings)

        # Count resources by type for summary
        resource_counts = {}
        for res in all_resources:
            rtype = res["type"]
            resource_counts[rtype] = resource_counts.get(rtype, 0) + 1

        self._print_summary(resource_counts, all_resources)

        if findings:
            console.print(f"\n  [bold yellow]Findings:[/bold yellow] {len(findings)} misconfigurations detected")
            sev_counts = {}
            for f in findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                if sev in sev_counts:
                    color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "dim"}.get(sev, "white")
                    console.print(f"    [{color}]{sev}: {sev_counts[sev]}[/{color}]")

        return {
            "resources": all_resources,
            "resource_counts": resource_counts,
            "findings": findings,
        }

    def _run_rules(self, resources: list[dict]) -> list:
        """Load YAML rules and evaluate them against discovered resources."""
        # Try multiple paths for rules directory (works from project root or package dir)
        rules_paths = [
            Path(self.rules_dir),
            Path(__file__).resolve().parent.parent.parent / "config" / "rules",
        ]
        for rpath in rules_paths:
            if rpath.exists():
                self.rule_engine.rules_dir = rpath
                break

        count = self.rule_engine.load_rules()
        console.print(f"\n  Loaded [cyan]{count}[/cyan] security rules")
        return self.rule_engine.evaluate(resources)

    def _run_secret_scan(self, resources: list[dict]) -> list:
        """Run the secret scanner against discovered resources."""
        console.print("\n  Running secret scanner...")
        secret_findings = self.secret_scanner.scan_all(resources)
        if secret_findings:
            console.print(f"  [bold red]Secret scan:[/bold red] {len(secret_findings)} exposed secrets detected")
        else:
            console.print("  [green]Secret scan:[/green] no exposed secrets found")
        return secret_findings

    def _run_collectors(self) -> list[dict]:
        """Run all enabled collectors and merge their results."""
        all_resources = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for name in self.enabled_collectors:
                if name not in COLLECTOR_REGISTRY:
                    console.print(f"  [yellow]Unknown collector: {name}, skipping[/yellow]")
                    continue

                task = progress.add_task(f"Collecting {name} resources...", total=None)
                collector_class = COLLECTOR_REGISTRY[name]
                collector = collector_class(
                    clients=self.clients,
                    resource_group=self.resource_group,
                )

                try:
                    resources = collector.collect()
                    all_resources.extend(resources)
                    progress.update(
                        task,
                        description=f"[green]Collected {len(resources)} {name} resources[/green]",
                        completed=True,
                    )
                except Exception:
                    # Log the full exception to file for debugging,
                    # but only show a generic message in the console
                    # to avoid leaking internal details (Azure SDK errors
                    # can contain endpoint URLs and credential hints)
                    import logging
                    logging.getLogger("azsploitmapper.scanner").exception(
                        "Failed to collect %s resources", name,
                    )
                    progress.update(
                        task,
                        description=f"[red]Failed to collect {name} resources[/red]",
                        completed=True,
                    )

        return all_resources

    def _print_summary(self, resource_counts: dict, resources: list[dict]):
        """Print a summary of discovered resources."""
        total = len(resources)
        console.print(f"\n  [bold]Discovery complete:[/bold] {total} resources found\n")

        for rtype, count in sorted(resource_counts.items()):
            # Show short type name (e.g. "virtualMachines" from "Microsoft.Compute/virtualMachines")
            short_name = rtype.split("/")[-1] if "/" in rtype else rtype
            console.print(f"    {short_name}: [cyan]{count}[/cyan]")
