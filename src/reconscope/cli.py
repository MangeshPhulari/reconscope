from __future__ import annotations

import sys
from argparse import ArgumentParser
from pathlib import Path

from .core import ReconScope, MultiSourceMiner
from .ui import console, make_progress, print_banner, print_results


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="reconscope",
        description="Advanced Parameter & Endpoint Enumeration — v3.0",
        epilog="Use only on systems you own or have explicit permission to assess.",
    )

    # --- Targets ---
    parser.add_argument("targets", nargs="*", help="Target domains or URLs")
    parser.add_argument("--input", "-i", type=Path, help="File containing one target per line")

    # --- Crawl behaviour ---
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=250, help="Maximum pages per target (default: 250)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent fetches (default: 10)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--no-crawl", action="store_true", help="Skip live crawl; Passive-only mode")
    parser.add_argument("--allow-subdomains", action="store_true", help="Allow subdomains within scope")
    parser.add_argument("--allow-external", action="store_true", help="Allow external hosts")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-filter-extensions", action="store_true", help="Disable static asset filtering")

    # --- Passive Sources ---
    parser.add_argument("--wayback", "-w", action="store_true", help="Enable multi-source passive mining (Wayback, OTX, etc.)")
    parser.add_argument("--no-passive", action="store_true", help="Disable all passive mining")

    # --- Request customisation ---
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument(
        "--header", "-H", action="append", dest="headers", metavar="Key:Value",
        help="Extra request header (repeatable)"
    )
    parser.add_argument("--user-agent", help="Override User-Agent (default: random rotation)")
    parser.add_argument("--threads", type=int, default=10, dest="concurrency", help="Alias for concurrency")

    # --- Output ---
    parser.add_argument("--output", "-o", choices=("text", "json", "csv"), default="text", help="Output format")
    parser.add_argument("--output-file", type=Path, help="Write output to file instead of stdout")
    parser.add_argument("--output-dir", type=Path,
                        help="Directory to save results (default when --wayback: ./results/)")
    parser.add_argument("--placeholder", "-p", default="FUZZ",
                        help="Replace all query-param values with this string (default: FUZZ)")
    parser.add_argument("--params-only", action="store_true", help="Print only discovered parameter names")
    parser.add_argument("--endpoints-only", action="store_true", help="Print only discovered endpoint URLs")
    parser.add_argument("--silent", "-s", action="store_true", help="Suppress banner and progress output")

    return parser


def load_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.input:
        targets.extend(
            line.strip()
            for line in args.input.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return targets


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for h in (header_list or []):
        if ":" in h:
            k, _, v = h.partition(":")
            result[k.strip()] = v.strip()
    return result


def _save_passive_file(domain: str, urls: list[str], out_dir: Path) -> Path:
    """Save FUZZ-parameterised URLs to results/domain.txt and return the path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{domain}.txt"
    out_file.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
    return out_file


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = load_targets(args)

    if not targets:
        parser.error("provide at least one target domain, URL, or --input file")

    print_banner(silent=args.silent)

    extra_headers = parse_headers(args.headers)
    filter_ext = not args.no_filter_extensions
    placeholder = args.placeholder  # default "FUZZ"

    # ------------------------------------------------------------------ #
    # Multi-Source Passive Mining                                          #
    # ------------------------------------------------------------------ #
    passive_results: dict[str, list[str]] = {}
    passive_params: dict[str, set] = {}
    miner: MultiSourceMiner | None = None

    # In v3, --wayback is an alias for all passive sources unless --no-passive is used
    if (args.wayback or not args.no_passive) and not args.no_passive:
        miner = MultiSourceMiner(
            placeholder=placeholder,
            proxies={"http": args.proxy, "https": args.proxy} if args.proxy else {},
            filter_extensions=filter_ext,
            timeout=args.timeout,
        )

        # Determine output directory (default: ./results/)
        out_dir = args.output_dir or Path("results")

        for target in targets:
            # Clean domain for mining
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]

            if not args.silent:
                console.print(f"\n[bold green][Passive][/bold green] Mining [cyan]{domain}[/cyan] from multiple sources...")

            urls, params = miner.mine_all(domain)
            passive_results[target] = urls
            passive_params[target] = params

            if not urls:
                if not args.silent:
                    console.print(f"  [yellow]⚠  No archived parameterised URLs found for {domain}[/yellow]")
                continue

            if not args.silent:
                console.print(f"  [green]✔  {len(urls)}[/green] parameterised URLs discovered across all sources")

            # Always print the FUZZ URLs to stdout
            if not args.output_file and not args.silent:
                sys.stdout.write("\n".join(urls[:10]) + (f"\n... and {len(urls)-10} more\n" if len(urls) > 10 else "\n"))
            elif not args.output_file:
                sys.stdout.write("\n".join(urls) + "\n")

    # ------------------------------------------------------------------ #
    # No-crawl mode: Passive-only, skip live HTTP crawl                   #
    # ------------------------------------------------------------------ #
    if args.no_crawl:
        if args.no_passive:
            parser.error("--no-crawl requires passive mining unless you provide targets for crawling")

        # Build a skeleton ReconResult from passive data
        from .core import ReconResult
        result = ReconResult(target=";".join(targets))
        for target, urls in passive_results.items():
            result.wayback_urls.extend(urls)
            if target in passive_params:
                for p in passive_params[target]:
                    key = f"{p.name}|{p.source}|{p.url or ''}"
                    result.parameters.setdefault(key, p)

        if args.params_only:
            names = sorted({p.name for p in result.parameters.values()})
            if names:
                sys.stdout.write("\n".join(names) + "\n")
            elif not args.silent:
                console.print("[yellow]No parameters found.[/yellow]")

        if not args.silent:
            console.print(
                f"\n[bold]Summary:[/bold] "
                f"[green]{len(result.wayback_urls)}[/green] Passive URLs  |  "
                f"[yellow]{len(result.parameters)}[/yellow] unique parameters"
            )
        return 0

    # Determine output directory (default: ./results/)
    out_dir = args.output_dir or Path("results")

    # ------------------------------------------------------------------ #
    # Live crawl                                                           #
    # ------------------------------------------------------------------ #
    engine = ReconScope(
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        timeout=args.timeout,
        user_agent=args.user_agent,
        rotate_ua=not args.user_agent,
        allow_subdomains=args.allow_subdomains,
        allow_external=args.allow_external,
        verify_ssl=not args.insecure,
        proxy=args.proxy,
        delay=args.delay,
        extra_headers=extra_headers,
        filter_extensions=filter_ext,
        placeholder=placeholder if placeholder != "FUZZ" else None,
    )

    progress = make_progress(silent=args.silent)
    with progress:
        task = progress.add_task("[cyan]Crawling...", total=args.max_pages * len(targets))

        def _cb(visited: int, _max: int) -> None:
            progress.update(task, completed=visited)

        engine.progress_callback = _cb
        result = engine.run(targets)
        progress.update(task, completed=args.max_pages * len(targets))

    # Attach passive URLs to crawl result
    for target, urls in passive_results.items():
        result.wayback_urls.extend(u for u in urls if u not in result.wayback_urls)
        if target in passive_params:
            for p in passive_params[target]:
                # Unique key to avoid duplicates
                key = f"{p.name}|{p.source}|{p.url or ''}"
                result.parameters.setdefault(key, p)

    # ------------------------------------------------------------------ #
    # Build output for crawl results                                       #
    # ------------------------------------------------------------------ #
    if args.params_only:
        output = engine.export_params_only(result)
    elif args.endpoints_only:
        output = engine.export_endpoints_only(result)
    elif args.output == "json":
        output = engine.export_json(result)
    elif args.output == "csv":
        output = engine.export_csv(result)
    else:
        output = engine.export_text(result)

    # Final Save Logic
    if args.output_file:
        args.output_file.write_text(output, encoding="utf-8")
        if not args.silent:
            console.print(f"[bold green]Saved Report:[/bold green] {args.output_file}")
    else:
        # Default to saving in out_dir/target.txt (or target.json/csv)
        saved = engine.save_output_dir(result, out_dir, args.output)
        if not args.silent:
            console.print(f"[bold green]Report Saved:[/bold green] {saved}")
        
        # Also print to stdout if not silent
        if not args.silent:
            # We don't print the whole huge output to terminal again, just a summary
            print_results(result, params_only=args.params_only, endpoints_only=args.endpoints_only)

    return 0
