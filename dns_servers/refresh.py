"""Rebuild nameservers.txt: pull the public-dns.info candidate pool, then keep only the
resolvers that survive `dns_servers.validate` right now.

The published list is our own measurement. The upstream pool is a seed, nothing more —
its own `checked_at` stamps stopped moving in August 2023, so liveness has to come from
probing, not from the feed.
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import random
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from dns_servers.validate import (
    DEFAULT_CONCURRENCY,
    DEFAULT_FEED_TIMEOUT_S,
    DEFAULT_PROBES,
    DEFAULT_TIMEOUT_S,
    URLHAUS_FEED_URL,
    ValidationReport,
    validate,
    write_atomic,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_URL = "https://public-dns.info/nameserver/nameservers.json"
DEFAULT_OUTPUT = REPO_ROOT / "nameservers.txt"
DEFAULT_META_OUTPUT = REPO_ROOT / "nameservers.meta.json"
MIN_RELIABILITY = 0.99
DOWNLOAD_TIMEOUT_S = 120.0
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_RETRY_DELAY_S = 5.0
MIN_KEEP_RATIO = 0.5
# The floor that guards a curated list is meaningless against the raw pool: upstream's own
# weekly probe keeps ~3.7% of it. Week-on-week collapse is the signal that matters here.
REFRESH_MIN_PASS_RATE = 0.01
EXIT_PASS_RATE_FLOOR = 2
EXIT_COLLAPSED = 4

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def parse_address(*, text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def sort_key(nameserver: str) -> tuple[int, int]:
    address = ipaddress.ip_address(nameserver)
    return (address.version, int(address))


def download_candidates(*, url: str = SOURCE_URL) -> list[dict]:
    last_error: Exception | None = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            response = httpx.get(url, timeout=DOWNLOAD_TIMEOUT_S, follow_redirects=True)
            response.raise_for_status()
            return response.json()
        except Exception as error:
            last_error = error
            logging.warning(
                "download attempt %d/%d failed: %s: %s",
                attempt,
                DOWNLOAD_ATTEMPTS,
                type(error).__name__,
                error,
            )
            if attempt < DOWNLOAD_ATTEMPTS:
                time.sleep(DOWNLOAD_RETRY_DELAY_S)
    raise RuntimeError(f"could not download {url}") from last_error


def select_candidates(
    *,
    records: list[dict],
    min_reliability: float = MIN_RELIABILITY,
    include_ipv6: bool = False,
) -> list[str]:
    selected: set[str] = set()
    for record in records:
        if (record.get("reliability") or 0) < min_reliability:
            continue
        address = parse_address(text=record.get("ip", ""))
        if address is None or not address.is_global:
            continue
        if address.version == 6 and not include_ipv6:
            continue
        selected.add(str(address))
    return sorted(selected, key=sort_key)


def source_last_checked(*, records: list[dict]) -> str | None:
    stamps = [record["checked_at"] for record in records if record.get("checked_at")]
    return max(stamps) if stamps else None


def previous_count(*, path: Path) -> int:
    if not path.is_file():
        return 0
    return len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])


def collapsed(*, healthy: list[str], path: Path) -> bool:
    previous = previous_count(path=path)
    if not previous:
        return False
    floor = int(previous * MIN_KEEP_RATIO)
    if len(healthy) >= floor:
        return False
    logging.error(
        "%d healthy resolvers is under %d, half of last run's %d — a network failure here is "
        "likelier than half the internet's resolvers dying in a week",
        len(healthy),
        floor,
        previous,
    )
    return True


def write_meta(
    *,
    path: Path,
    report: ValidationReport,
    candidates: list[str],
    records: list[dict],
    source_url: str,
) -> None:
    meta = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "source_url": source_url,
        "source_records": len(records),
        "source_last_checked_at": source_last_checked(records=records),
        "probed": len(candidates),
        "healthy": len(report.good),
        "pass_rate": round(report.pass_rate, 4),
        "elapsed_s": round(report.elapsed_s, 1),
        "status_counts": dict(report.status_counts.most_common()),
    }
    path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    logging.info("wrote %s", path)


def summarize(*, report: ValidationReport, candidates: list[str]) -> str:
    top = ", ".join(f"{status}={count}" for status, count in report.status_counts.most_common(4))
    return f"{len(report.good)}/{len(candidates)} resolvers healthy ({top})"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild nameservers.txt from a probed public resolver pool."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--meta-output", type=Path, default=DEFAULT_META_OUTPUT)
    parser.add_argument("--source-url", default=SOURCE_URL)
    parser.add_argument("--min-reliability", type=float, default=MIN_RELIABILITY)
    parser.add_argument("--include-ipv6", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="probe only the first N candidates")
    parser.add_argument("--sample", type=int, default=0, help="probe a random N-candidate sample")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--probes", nargs="+", default=list(DEFAULT_PROBES))
    parser.add_argument("--min-pass-rate", type=float, default=REFRESH_MIN_PASS_RATE)
    parser.add_argument("--canary-feed", default=URLHAUS_FEED_URL)
    parser.add_argument("--feed-timeout", type=float, default=DEFAULT_FEED_TIMEOUT_S)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true", help="write even if the list collapsed")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args()


async def run(*, args: argparse.Namespace) -> int:
    records = download_candidates(url=args.source_url)
    logging.info(
        "%d candidates in source, newest checked_at %s",
        len(records),
        source_last_checked(records=records),
    )
    candidates = select_candidates(
        records=records,
        min_reliability=args.min_reliability,
        include_ipv6=args.include_ipv6,
    )
    if args.sample:
        candidates = sorted(random.sample(candidates, min(args.sample, len(candidates))), key=sort_key)
    if args.limit:
        candidates = candidates[: args.limit]
    if not candidates:
        logging.error("no candidates survived filtering")
        return 1

    report = await validate(
        resolvers=candidates,
        probes=tuple(args.probes),
        timeout=args.timeout,
        concurrency=args.concurrency,
        canary_feed=args.canary_feed,
        feed_timeout=args.feed_timeout,
    )

    if report.pass_rate < args.min_pass_rate:
        logging.error(
            "pass rate %.2f below floor %.2f — refusing to write", report.pass_rate, args.min_pass_rate
        )
        return EXIT_PASS_RATE_FLOOR
    if collapsed(healthy=report.good, path=args.output) and not args.force:
        return EXIT_COLLAPSED

    print(summarize(report=report, candidates=candidates))
    if args.dry_run:
        logging.info("dry-run, not writing output")
        return 0

    write_atomic(path=args.output, lines=sorted(report.good, key=sort_key))
    logging.info("wrote %d resolvers to %s", len(report.good), args.output)
    write_meta(
        path=args.meta_output,
        report=report,
        candidates=candidates,
        records=records,
        source_url=args.source_url,
    )
    return 0


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return asyncio.run(run(args=args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
