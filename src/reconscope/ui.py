"""Rich terminal UI helpers for ReconScope."""
from __future__ import annotations

from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from .core import ReconResult

console = Console(highlight=False)

BANNER = r"""
[bold cyan]
 ____                       ____
|  _ \ ___  ___ ___  _ __  / ___|  ___ ___  _ __   ___
| |_) / _ \/ __/ _ \| '_ \ \___ \ / __/ _ \| '_ \ / _ \
|  _ <  __/ (_| (_) | | | | ___) | (_| (_) | |_) |  __/
|_| \_\___|\___\___/|_| |_||____/ \___\___/| .__/ \___|
                                            |_|[/bold cyan]
[dim]  v4.0  |  Ultimate Pentest Edition (API, JS, Secrets)  |  by Mangesh Phulari[/dim]
"""


def print_banner(silent: bool = False) -> None:
    if silent:
        return
    console.print(BANNER)
    console.rule("[dim]Use only on systems you own or have explicit permission to assess.[/dim]")
    console.print()


def make_progress(silent: bool = False) -> Progress:
    """Return a Rich Progress instance for live crawl tracking."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        disable=silent,
    )


def print_results(
    result: "ReconResult",
    params_only: bool = False,
    endpoints_only: bool = False,
    flat: bool = False,
    silent: bool = False,
) -> None:
    """Print a color-coded summary of the recon result."""
    if silent:
        return

    if flat:
        # In flat mode, URLs were already printed to stdout. Just show summary table.
        _print_summary_table(result)
        return

    console.print()

    if not params_only:
        _print_endpoints(result)

    if not endpoints_only:
        _print_parameters(result)

    if result.wayback_urls:
        _print_passive(result)

    if result.secrets:
        _print_secrets(result)

    _print_summary_table(result)


def _print_endpoints(result: "ReconResult") -> None:
    if not result.endpoints:
        console.print("[dim]No endpoints discovered.[/dim]")
        return
    console.print(f"[bold cyan]Endpoints[/bold cyan] — [dim]{len(result.endpoints)} found[/dim]")
    for ep in sorted(result.endpoints.values(), key=lambda e: e.url):
        console.print(f"  [cyan]{ep.url}[/cyan]  [dim]\\[{ep.source}][/dim]")
    console.print()


def _print_parameters(result: "ReconResult") -> None:
    if not result.parameters:
        console.print("[dim]No parameters discovered.[/dim]")
        return
    console.print(f"[bold yellow]Parameters[/bold yellow] — [dim]{len(result.parameters)} found[/dim]")
    for param in sorted(result.parameters.values(), key=lambda p: p.name):
        url_suffix = f"  [dim]{param.url}[/dim]" if param.url else ""
        console.print(f"  [yellow]{param.name}[/yellow]  [dim]\\[{param.source}][/dim]{url_suffix}")
    console.print()


def _print_passive(result: "ReconResult") -> None:
    console.print(f"[bold green]Passive URLs[/bold green] — [dim]{len(result.wayback_urls)} found[/dim]")
    for url in sorted(result.wayback_urls):
        console.print(f"  [green]{url}[/green]")
    console.print()


def _print_secrets(result: "ReconResult") -> None:
    console.print(f"[bold red]Secrets Found[/bold red] — [dim]{len(result.secrets)} potential leaks[/dim]")
    for s in result.secrets:
        console.print(f"  [red]\\[{s.type}][/red] {s.value} [dim]({s.url})[/dim]")
    console.print()


def _print_summary_table(result: "ReconResult") -> None:
    table = Table(title="[bold]Scan Summary[/bold]", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right", style="bold white")
    table.add_row("Pages visited", str(len(result.visited_pages)))
    table.add_row("Endpoints", str(len(result.endpoints)))
    table.add_row("Parameters", str(len(result.parameters)))
    table.add_row("Passive URLs", str(len(result.wayback_urls)))
    table.add_row("Secrets", str(len(result.secrets)))
    console.print(table)
    console.print()
