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
[dim]  v4.5  |  Ultimate Pentest Edition (API, JS, Secrets)  |  by Mangesh Phulari[/dim]
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
    generated_url_count: int | None = None,
) -> None:
    """Print a color-coded summary of the recon result."""
    if silent:
        return

    console.print()
    _print_summary_table(result, generated_url_count=generated_url_count, flat=flat)


def _print_summary_table(
    result: "ReconResult",
    generated_url_count: int | None = None,
    flat: bool = False,
) -> None:
    table = Table(
        title="[bold]Scan Summary[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Metric", style="dim")
    table.add_column("Count", justify="right", style="bold white")

    table.add_row("Pages visited", str(len(result.visited_pages)))

    # Count target-only endpoints
    from urllib.parse import urlparse
    target_domain = result.target.replace("https://", "").replace("http://", "").split("/")[0]
    target_ep_count = sum(
        1 for ep in result.endpoints.values()
        if urlparse(ep.url).netloc.lower() in (target_domain, f"www.{target_domain}")
        or urlparse(ep.url).netloc.lower().endswith(f".{target_domain}")
    )
    table.add_row("Endpoints Found", str(target_ep_count))

    # Real parameterized URLs (target-only, non-static)
    static_exts = {".js", ".css", ".woff", ".woff2", ".png", ".jpg", ".gif", ".svg", ".ico", ".map", ".ttf", ".eot"}
    param_urls = {
        p.url for p in result.parameters.values()
        if p.url
        and (urlparse(p.url).netloc.lower() == target_domain
             or urlparse(p.url).netloc.lower().endswith(f".{target_domain}"))
        and not any(urlparse(p.url).path.lower().endswith(ext) for ext in static_exts)
    }
    table.add_row("Parameterized URLs (raw)", str(len(param_urls)))
    table.add_row("Unique Param Names", str(len({p.name for p in result.parameters.values()})))

    # Show the actually generated/written URL count if flat mode
    if flat and generated_url_count is not None:
        table.add_row("[bold green]URLs Written to File[/bold green]", f"[bold green]{generated_url_count}[/bold green]")

    table.add_row("Passive URLs", str(len(result.wayback_urls)))

    if result.secrets:
        table.add_row("[bold red]Secrets Found[/bold red]", f"[bold red]{len(result.secrets)}[/bold red]")
    else:
        table.add_row("Secrets Found", "0")

    console.print(table)

    # Show secrets details if any
    if result.secrets:
        console.print()
        console.print("[bold red]⚠  Potential Secrets / Leaks Detected![/bold red]")
        for s in result.secrets:
            console.print(f"  [red][{s.type}][/red]  {s.value}  [dim]({s.url})[/dim]")

    console.print()
