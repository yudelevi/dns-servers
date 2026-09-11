#!/usr/bin/env python3
"""Validate public DNS resolvers — drop ones that timeout, refuse, lie, or can't recurse.

Every resolver must answer each probe domain with NOERROR, at least one answer, and the
RA flag set, inside the timeout. Survivors then face two poisoning gates: a random
non-existent domain that must NOT resolve, and live canary hosts from a malware-URL feed
that must NOT come back NXDOMAIN, empty, or pointing at a known sinkhole range.

Usable as a library (`validate`) or standalone against a file of resolver IPs.
"""

import argparse
import asyncio
import ipaddress
import logging
import os
import secrets
import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "nameservers.txt"
DEFAULT_OUTPUT = REPO_ROOT / "nameservers_validated.txt"
DEFAULT_TIMEOUT_S = 2.0
DEFAULT_MAX_INPUT_AGE_DAYS = 30
EXIT_STALE_INPUT = 3
DEFAULT_CONCURRENCY = 500
DEFAULT_PROBES = ("google.com", "cloudflare.com", "wikipedia.org")
DEFAULT_MIN_PASS_RATE = 0.30
QTYPE_A = 1
QCLASS_IN = 1
FLAG_QR = 0x8000
FLAG_RA = 0x0080
RCODE_MASK = 0x000F
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3

CONTROL_RESOLVERS = ("1.1.1.1", "8.8.8.8")
URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
FALLBACK_CANARIES = ("internetbadguys.com",)
N_CANARIES = 3
MIN_CANARIES = 1
MAX_CANARY_SCAN = 60
DEFAULT_FEED_TIMEOUT_S = 10.0
KNOWN_BLOCK_NETWORKS = (ipaddress.ip_network("146.112.61.0/24"),)

CANARY_HOST_DENYLIST = frozenset(
    {
        "google.com",
        "gstatic.com",
        "github.com",
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "bitbucket.org",
        "sourceforge.net",
        "amazonaws.com",
        "cloudfront.net",
        "googleusercontent.com",
        "googleapis.com",
        "blogspot.com",
        "wordpress.com",
        "weebly.com",
        "wixsite.com",
        "herokuapp.com",
        "netlify.app",
        "vercel.app",
        "pages.dev",
        "web.app",
        "firebaseapp.com",
        "dropbox.com",
        "dropboxusercontent.com",
        "sharepoint.com",
        "discordapp.com",
        "discord.com",
        "t.me",
        "telegram.org",
        "archive.org",
        "cloudflare.net",
        "cloudflarestorage.com",
        "r2.dev",
        "backblazeb2.com",
        "digitaloceanspaces.com",
        "azureedge.net",
        "windows.net",
    }
)


def is_denylisted_host(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in CANARY_HOST_DENYLIST)


def encode_qname(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    out = bytearray()
    for label in parts:
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def build_query(qname: str, qtype: int = QTYPE_A) -> tuple[int, bytes]:
    txid = secrets.randbits(16)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    body = encode_qname(name=qname) + struct.pack(">HH", qtype, QCLASS_IN)
    return txid, header + body


class DnsHeader(NamedTuple):
    txid: int
    flags: int
    ancount: int


def parse_header(packet: bytes) -> DnsHeader:
    if len(packet) < 12:
        raise ValueError(f"short packet ({len(packet)} bytes)")
    txid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", packet[:12])
    return DnsHeader(txid=txid, flags=flags, ancount=ancount)


def _skip_name(packet: bytes, offset: int) -> int:
    while True:
        if offset >= len(packet):
            raise ValueError("name overruns packet")
        length = packet[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length


def parse_first_a_record(packet: bytes) -> str | None:
    if len(packet) < 12:
        return None
    try:
        qdcount, ancount = struct.unpack(">HH", packet[4:8])
        offset = 12
        for _ in range(qdcount):
            offset = _skip_name(packet, offset)
            offset += 4
        for _ in range(ancount):
            offset = _skip_name(packet, offset)
            if offset + 10 > len(packet):
                return None
            rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", packet[offset : offset + 10])
            offset += 10
            if rtype == QTYPE_A and rdlength == 4:
                return socket.inet_ntoa(packet[offset : offset + 4])
            offset += rdlength
    except (ValueError, struct.error):
        return None
    return None


def status_from_flags(*, flags: int, ancount: int) -> str:
    rcode = flags & RCODE_MASK
    if rcode == RCODE_NXDOMAIN:
        return "nxdomain"
    if rcode != RCODE_NOERROR:
        return f"rcode_{rcode}"
    if not (flags & FLAG_RA):
        return "no_ra"
    if ancount < 1:
        return "no_answer"
    return "ok"


def is_sinkhole(*, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_unspecified or addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
        return True
    return any(addr in net for net in KNOWN_BLOCK_NETWORKS)


class ProbeResult(NamedTuple):
    status: str
    ms: float | None
    ip: str | None


async def probe_one(
    *,
    server: str,
    qname: str,
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> ProbeResult:
    txid, query = build_query(qname=qname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.setblocking(False)
    try:
        start = loop.time()
        sock.sendto(query, (server, 53))
        while True:
            elapsed = loop.time() - start
            remaining = timeout - elapsed
            if remaining <= 0:
                return ProbeResult(status="timeout", ms=None, ip=None)
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=remaining)
            except TimeoutError:
                return ProbeResult(status="timeout", ms=None, ip=None)
            try:
                resp_txid, flags, ancount = parse_header(packet=data)
            except ValueError:
                return ProbeResult(status="malformed", ms=None, ip=None)
            if resp_txid != txid:
                continue
            status = status_from_flags(flags=flags, ancount=ancount)
            if status != "ok":
                return ProbeResult(status=status, ms=None, ip=None)
            return ProbeResult(
                status="ok", ms=(loop.time() - start) * 1000, ip=parse_first_a_record(packet=data)
            )
    except OSError as e:
        return ProbeResult(status=f"oserror:{e.errno}", ms=None, ip=None)
    finally:
        sock.close()


def classify_filtering(results: list[tuple[str, str | None]]) -> bool:
    for status, ip in results:
        if status in ("nxdomain", "no_answer"):
            return True
        if status == "ok" and ip is not None and is_sinkhole(ip=ip):
            return True
    return False


class ResolverResult(NamedTuple):
    server: str
    status: str
    slowest_ms: float | None


async def probe_resolver(
    *,
    server: str,
    probes: tuple[str, ...],
    canaries: tuple[str, ...],
    random_domains: tuple[str, ...],
    timeout: float,
    loop: asyncio.AbstractEventLoop,
    sem: asyncio.Semaphore,
) -> ResolverResult:
    async with sem:
        slowest_ms = 0.0
        for qname in probes:
            status, ms, _ip = await probe_one(server=server, qname=qname, timeout=timeout, loop=loop)
            if status != "ok":
                return ResolverResult(server=server, status=status, slowest_ms=ms)
            if ms is not None and ms > slowest_ms:
                slowest_ms = ms

        for rname in random_domains:
            status, _ms, ip = await probe_one(server=server, qname=rname, timeout=timeout, loop=loop)
            if status == "ok" and ip is not None:
                return ResolverResult(server=server, status="hijack", slowest_ms=slowest_ms)

        canary_results: list[tuple[str, str | None]] = []
        for cname in canaries:
            status, _ms, ip = await probe_one(server=server, qname=cname, timeout=timeout, loop=loop)
            canary_results.append((status, ip))
        if classify_filtering(canary_results):
            return ResolverResult(server=server, status="filtering", slowest_ms=slowest_ms)

        return ResolverResult(server=server, status="ok", slowest_ms=slowest_ms)


def read_resolvers(*, path: Path) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def write_atomic(*, path: Path, lines: list[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def random_nonexistent_domain(tld: str = "com") -> str:
    return f"{secrets.token_hex(10)}.{tld}"


def parse_feed(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host = urlparse(line).hostname if "://" in line else line.split("/", 1)[0]
        if not host:
            continue
        host = host.lower()
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if is_denylisted_host(host=host):
            continue
        if "." not in host or host in seen:
            continue
        seen.add(host)
        out.append(host)
    return out


def _http_get(url: str, timeout: float) -> str:
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"Refusing canary feed URL {url!r}: expected http(s)")
    response = httpx.get(url, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    return response.text


async def fetch_canaries(
    *,
    url: str,
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> list[str]:
    try:
        text = await loop.run_in_executor(None, lambda: _http_get(url, timeout))
    except Exception as e:
        logging.warning("canary feed fetch failed (%s): %s", url, e)
        return []
    hosts = parse_feed(text)
    logging.info("fetched %d candidate canaries from feed", len(hosts))
    return hosts


async def control_healthy(
    *,
    control: tuple[str, ...],
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> bool:
    for ctrl in control:
        status, _ms, _ip = await probe_one(server=ctrl, qname="google.com", timeout=timeout, loop=loop)
        if status == "ok":
            return True
    return False


async def select_live_canaries(
    *,
    candidates: list[str],
    control: tuple[str, ...],
    timeout: float,
    loop: asyncio.AbstractEventLoop,
    n: int,
    max_scan: int,
) -> list[str]:
    live: list[str] = []
    for host in candidates[:max_scan]:
        for ctrl in control:
            status, _ms, ip = await probe_one(server=ctrl, qname=host, timeout=timeout, loop=loop)
            if status == "ok" and ip is not None:
                live.append(host)
                break
        if len(live) >= n:
            break
    return live


def input_age_days(*, path: Path) -> float:
    # git only rewrites files whose content changed, so mtime tracks the upstream refresh.
    return (time.time() - path.stat().st_mtime) / 86400.0


class ValidationReport(NamedTuple):
    good: list[str]
    status_counts: Counter[str]
    elapsed_s: float

    @property
    def pass_rate(self) -> float:
        total = sum(self.status_counts.values())
        return len(self.good) / total if total else 0.0


async def resolve_canaries(
    *,
    canary_feed: str,
    feed_timeout: float,
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> tuple[str, ...]:
    candidates = await fetch_canaries(url=canary_feed, timeout=feed_timeout, loop=loop)
    if not candidates:
        candidates = list(FALLBACK_CANARIES)
        logging.warning("canary feed empty — using %d fallback canaries", len(candidates))

    if not await control_healthy(control=CONTROL_RESOLVERS, timeout=timeout, loop=loop):
        logging.warning("control resolvers unreachable — skipping filtering gate this run")
        return ()

    selected = await select_live_canaries(
        candidates=candidates,
        control=CONTROL_RESOLVERS,
        timeout=timeout,
        loop=loop,
        n=N_CANARIES,
        max_scan=MAX_CANARY_SCAN,
    )
    if len(selected) < MIN_CANARIES:
        logging.warning(
            "only %d live canaries (< %d) — skipping filtering gate this run", len(selected), MIN_CANARIES
        )
        return ()
    return tuple(selected)


async def validate(
    *,
    resolvers: list[str],
    probes: tuple[str, ...] = DEFAULT_PROBES,
    timeout: float = DEFAULT_TIMEOUT_S,
    concurrency: int = DEFAULT_CONCURRENCY,
    canary_feed: str = URLHAUS_FEED_URL,
    feed_timeout: float = DEFAULT_FEED_TIMEOUT_S,
) -> ValidationReport:
    loop = asyncio.get_running_loop()
    canaries = await resolve_canaries(
        canary_feed=canary_feed,
        feed_timeout=feed_timeout,
        timeout=timeout,
        loop=loop,
    )
    logging.info("filtering gate canaries: %s", list(canaries))

    random_domains = (random_nonexistent_domain(tld="com"), random_nonexistent_domain(tld="net"))
    sem = asyncio.Semaphore(concurrency)
    logging.info(
        "validating %d resolvers via probes=%s timeout=%.1fs concurrency=%d",
        len(resolvers),
        list(probes),
        timeout,
        concurrency,
    )

    start = time.perf_counter()
    results = await asyncio.gather(
        *[
            probe_resolver(
                server=server,
                probes=probes,
                canaries=canaries,
                random_domains=random_domains,
                timeout=timeout,
                loop=loop,
                sem=sem,
            )
            for server in resolvers
        ]
    )
    elapsed = time.perf_counter() - start

    status_counts: Counter[str] = Counter()
    good: list[tuple[float, str]] = []
    for server, status, ms in results:
        status_counts[status] += 1
        if status == "ok":
            good.append((ms or 0.0, server))
    good.sort()

    report = ValidationReport(
        good=[server for _, server in good],
        status_counts=status_counts,
        elapsed_s=elapsed,
    )
    log_report(report=report, latencies=[ms for ms, _ in good])
    return report


def log_report(*, report: ValidationReport, latencies: list[float]) -> None:
    total = sum(report.status_counts.values())
    logging.info(
        "validated %d/%d (%.1f%%) in %.1fs",
        len(report.good),
        total,
        100.0 * report.pass_rate,
        report.elapsed_s,
    )
    logging.info("breakdown: %s", ", ".join(f"{k}={v}" for k, v in report.status_counts.most_common()))
    if latencies:
        logging.info(
            "latency: p50=%.0fms p95=%.0fms p99=%.0fms slowest=%.0fms",
            latencies[len(latencies) // 2],
            latencies[int(len(latencies) * 0.95)],
            latencies[int(len(latencies) * 0.99)],
            latencies[-1],
        )


async def run(*, args: argparse.Namespace) -> int:
    resolvers = read_resolvers(path=args.input)
    if not resolvers:
        logging.error("no resolvers read from %s", args.input)
        return 1

    age_days = input_age_days(path=args.input)
    stale_input = age_days > args.max_input_age_days
    if stale_input:
        logging.error(
            "input %s is %.0f days old (> %d) — the refresh looks dead, validating it anyway",
            args.input,
            age_days,
            args.max_input_age_days,
        )
    else:
        logging.info("input %s is %.0f days old", args.input, age_days)

    report = await validate(
        resolvers=resolvers,
        probes=tuple(args.probes),
        timeout=args.timeout,
        concurrency=args.concurrency,
        canary_feed=args.canary_feed,
        feed_timeout=args.feed_timeout,
    )

    if report.pass_rate < args.min_pass_rate:
        logging.error(
            "pass rate %.2f below floor %.2f — refusing to overwrite output",
            report.pass_rate,
            args.min_pass_rate,
        )
        return 2

    if args.dry_run:
        logging.info("dry-run, not writing output")
    else:
        write_atomic(path=args.output, lines=report.good)
        logging.info("wrote %s", args.output)
    return EXIT_STALE_INPUT if stale_input else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate public DNS resolvers — drop ones that timeout, refuse, lie, or can't recurse."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument(
        "--probes",
        nargs="+",
        default=list(DEFAULT_PROBES),
        help="domains to probe each resolver with (all must succeed)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--min-pass-rate",
        type=float,
        default=DEFAULT_MIN_PASS_RATE,
        help="abort without writing if fewer than this fraction pass (default 0.30)",
    )
    parser.add_argument(
        "--max-input-age-days",
        type=int,
        default=DEFAULT_MAX_INPUT_AGE_DAYS,
        help="exit nonzero (output still written) if the input list is older than this (default 30)",
    )
    parser.add_argument("--canary-feed", default=URLHAUS_FEED_URL)
    parser.add_argument("--feed-timeout", type=float, default=DEFAULT_FEED_TIMEOUT_S)
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return asyncio.run(run(args=args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
