from __future__ import annotations

import sys
from argparse import ArgumentParser
from pathlib import Path

from .core import ReconScope, WaybackMiner
from .ui import console, make_progress, print_banner, print_results


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="reconscope",
        description="Authorized endpoint & parameter enumeration — v2.0",
        epilog="Use only on systems you own or have explicit permission to assess.",
    )

    # --- Targets ---
    parser.add_argument("targets", nargs="*", help="Target domains or URLs")
    parser.add_argument("--input", "-i", type=Path, help="File containing one target per line")

    # --- Crawl behaviour ---
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=250, help="Maximum pages per target (default: 250)")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrent fetches (default: 8)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--no-crawl", action="store_true", help="Skip live crawl; run Wayback-only mode")
    parser.add_argument("--allow-subdomains", action="store_true", help="Allow subdomains within scope")
    parser.add_argument("--allow-external", action="store_true", help="Allow external hosts")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-filter-extensions", action="store_true", help="Disable static asset filtering")

    # --- Wayback Machine ---
    parser.add_argument("--wayback", "-w", action="store_true", help="Enable Wayback Machine parameter mining")

    # --- Request customisation ---
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument(
        "--header", "-H", action="append", dest="headers", metavar="Key:Value",
        help="Extra request header (repeatable)"
    )
    parser.add_argument("--user-agent", help="Override User-Agent (default: random rotation)")

    # --- Output ---
    parser.add_argument("--output", "-o", choices=("text", "json", "csv"), default="text", help="Output format")
    parser.add_argument("--output-file", type=Path, help="Write output to file instead of stdout")
    parser.add_argument("--output-dir", type=Path, help="Save one file per target in this directory")
    parser.add_argument("--placeholder", "-p", default="FUZZ",
                        help="Replace all query-param values with this string (default: FUZZ)")
    parser.add_argument("--params-only", action="store_true", help="Print only discovered parameter names")
    parser.add_argument("--endpoints-only", action="store_true", help="Print only discovered endpoints/URLs")
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = load_targets(args)

    if not targets:
        parser.error("provide at least one target domain, URL, or --input file")

    print_banner(silent=args.silent)

    extra_headers = parse_headers(args.headers)
    filter_ext = not args.no_filter_extensions

    # ------------------------------------------------------------------ #
    # Wayback Machine mining                                               #
    # ------------------------------------------------------------------ #
    wayback_results: dict[str, list[str]] = {}
    if args.wayback:
        miner = WaybackMiner(
            placeholder=args.placeholder,
            proxies={"http": args.proxy, "https": args.proxy} if args.proxy else {},
            filter_extensions=filter_ext,
        )
        for target in targets:
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]
            if not args.silent:
                console.print(f"[bold green][Wayback][/bold green] Mining [cyan]{domain}[/cyan] ...")
            urls = miner.mine(domain)
            wayback_results[target] = urls
            if not args.silent:
                console.print(f"  → [green]{len(urls)}[/green] historical URLs found")

    # ------------------------------------------------------------------ #
    # Live crawl                                                           #
    # ------------------------------------------------------------------ #
    progress = make_progress(silent=args.silent or args.no_crawl)

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
        placeholder=args.placeholder if args.placeholder != "FUZZ" else None,
    )

    if args.no_crawl:
        # Build a skeleton result from Wayback data only
        from .core import ReconResult, DiscoveredParameter
        result = ReconResult(target=";".join(targets))
        for target, urls in wayback_results.items():
            result.wayback_urls.extend(urls)
            for p in miner.extract_parameters(urls):
                key = f"{p.name}|{p.source}|{p.url or ''}"
                result.parameters.setdefault(key, p)
    else:
        with progress:
            task = progress.add_task("[cyan]Crawling...", total=args.max_pages * len(targets))

            def _cb(visited: int, _max: int) -> None:
                progress.update(task, completed=visited)

            engine.progress_callback = _cb
            result = engine.run(targets)
            progress.update(task, completed=args.max_pages * len(targets))

        # Attach Wayback URLs to result
        for target, urls in wayback_results.items():
            result.wayback_urls.extend(u for u in urls if u not in result.wayback_urls)
            if args.wayback:
                for p in miner.extract_parameters(urls):
                    key = f"{p.name}|{p.source}|{p.url or ''}"
                    result.parameters.setdefault(key, p)

    # ------------------------------------------------------------------ #
    # Build output                                                         #
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

    # Rich pretty-print (only for non-machine-readable modes without a file target)
    if not args.silent and not args.params_only and not args.endpoints_only and not args.output_file and args.output == "text":
        print_results(result, params_only=args.params_only, endpoints_only=args.endpoints_only, silent=args.silent)
        # Also dump plain-text for pipeable output
        sys.stdout.write(output + "\n")
        return 0

    if args.output_dir:
        saved = engine.save_output_dir(result, args.output_dir, args.output)
        if not args.silent:
            console.print(f"[bold green]Saved:[/bold green] {saved}")
    elif args.output_file:
        args.output_file.write_text(output, encoding="utf-8")
        if not args.silent:
            console.print(f"[bold green]Saved:[/bold green] {args.output_file}")
    else:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")

    if not args.silent:
        print_results(result, params_only=args.params_only, endpoints_only=args.endpoints_only, silent=False)

    return 0
