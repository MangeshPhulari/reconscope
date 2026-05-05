from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import sys

from .core import ReconScope


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(prog="reconscope", description="Authorized endpoint and parameter enumeration")
    parser.add_argument("targets", nargs="*", help="Target domains or URLs")
    parser.add_argument("--input", type=Path, help="File containing one target per line")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--max-pages", type=int, default=250, help="Maximum pages per target")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrent fetches")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--allow-subdomains", action="store_true", help="Allow subdomains within scope")
    parser.add_argument("--allow-external", action="store_true", help="Allow external hosts discovered during crawl")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--output", choices=("text", "json", "csv"), default="text", help="Output format")
    parser.add_argument("--output-file", type=Path, help="Write output to a file instead of stdout")
    return parser


def load_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.input:
        targets.extend(line.strip() for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip())
    return targets


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = load_targets(args)
    if not targets:
        parser.error("provide at least one target domain, URL, or --input file")

    engine = ReconScope(
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        timeout=args.timeout,
        allow_subdomains=args.allow_subdomains,
        allow_external=args.allow_external,
        verify_ssl=not args.insecure,
    )
    result = engine.run(targets)

    if args.output == "json":
        output = engine.export_json(result)
    elif args.output == "csv":
        output = engine.export_csv(result)
    else:
        output = engine.export_text(result)

    if args.output_file:
        args.output_file.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
        if not output.endswith("\n"):
            sys.stdout.write("\n")
    return 0
