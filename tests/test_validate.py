import asyncio
import socket
import struct

import dns_servers.validate as vr
from dns_servers.validate import (
    classify_filtering,
    is_denylisted_host,
    is_sinkhole,
    parse_feed,
    parse_first_a_record,
    random_nonexistent_domain,
    status_from_flags,
)


def _build_response(*, qname: str, answer_ip: str | None, ancount: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, ancount, 0, 0)
    q = bytearray()
    for label in qname.split("."):
        q.append(len(label))
        q.extend(label.encode("ascii"))
    q.append(0)
    q += struct.pack(">HH", 1, 1)
    body = bytes(q)
    if answer_ip is not None:
        rdata = socket.inet_aton(answer_ip)
        body += struct.pack(">HHHIH", 0xC00C, 1, 1, 300, len(rdata)) + rdata
    return header + body


def test_parse_first_a_record_present():
    pkt = _build_response(qname="a.com", answer_ip="93.184.216.34")
    assert parse_first_a_record(packet=pkt) == "93.184.216.34"


def test_parse_first_a_record_no_answer():
    pkt = _build_response(qname="a.com", answer_ip=None, ancount=0)
    assert parse_first_a_record(packet=pkt) is None


def test_parse_first_a_record_short_packet():
    assert parse_first_a_record(packet=b"\x00\x00") is None


def test_is_sinkhole_unspecified_and_private():
    assert is_sinkhole(ip="0.0.0.0") is True
    assert is_sinkhole(ip="127.0.0.1") is True
    assert is_sinkhole(ip="10.1.2.3") is True
    assert is_sinkhole(ip="192.168.0.5") is True


def test_is_sinkhole_known_block_range():
    assert is_sinkhole(ip="146.112.61.106") is True


def test_is_sinkhole_real_public_ip():
    assert is_sinkhole(ip="142.250.72.110") is False
    assert is_sinkhole(ip="1.1.1.1") is False


def test_is_sinkhole_garbage():
    assert is_sinkhole(ip="not-an-ip") is True


SAMPLE_FEED = """# urlhaus dump
# comment line
http://evil-one.example/x.exe
https://evil-two.example:8080/payload
http://evil-one.example/another
http://203.0.113.5/bare-ip-host
not-a-url-line
http://Evil-Three.EXAMPLE/Path
"""


def test_parse_feed_extracts_dedup_lowercased_hostnames():
    hosts = parse_feed(text=SAMPLE_FEED)
    assert hosts == ["evil-one.example", "evil-two.example", "evil-three.example"]


def test_parse_feed_drops_bare_ips():
    assert parse_feed(text="http://198.51.100.7/x") == []


def test_parse_feed_empty():
    assert parse_feed(text="# only comments\n\n") == []


def test_random_nonexistent_domain_shape_and_uniqueness():
    a = random_nonexistent_domain(tld="com")
    b = random_nonexistent_domain(tld="net")
    label_a, _, tld_a = a.partition(".")
    assert len(label_a) == 20 and all(c in "0123456789abcdef" for c in label_a)
    assert tld_a == "com"
    assert b.endswith(".net")
    assert a != b


def test_classify_filtering_nxdomain_is_filtered():
    assert classify_filtering(results=[("ok", "1.2.3.4"), ("nxdomain", None)]) is True


def test_classify_filtering_no_answer_is_filtered():
    assert classify_filtering(results=[("no_answer", None)]) is True


def test_classify_filtering_sinkhole_ip_is_filtered():
    assert classify_filtering(results=[("ok", "0.0.0.0")]) is True


def test_classify_filtering_clean_real_ips():
    assert classify_filtering(results=[("ok", "93.184.216.34"), ("ok", "142.250.72.110")]) is False


def test_classify_filtering_timeout_is_not_filtering():
    assert classify_filtering(results=[("timeout", None)]) is False


def test_status_from_flags_nxdomain():
    flags = 0x8183  # QR set, RA set, RCODE=3
    assert status_from_flags(flags=flags, ancount=0) == "nxdomain"


def test_status_from_flags_no_ra():
    flags = 0x8000  # QR set, RA clear, RCODE=0
    assert status_from_flags(flags=flags, ancount=1) == "no_ra"


def test_status_from_flags_no_answer():
    flags = 0x8080  # QR set, RA set, RCODE=0
    assert status_from_flags(flags=flags, ancount=0) == "no_answer"


def test_status_from_flags_ok():
    flags = 0x8080
    assert status_from_flags(flags=flags, ancount=2) == "ok"


def test_status_from_flags_other_rcode():
    flags = 0x8082  # RCODE=2 SERVFAIL
    assert status_from_flags(flags=flags, ancount=0) == "rcode_2"


def _run(coro):
    return asyncio.run(coro)


def _fake_probe(mapping: dict[str, tuple[str, float | None, str | None]]):
    async def _probe(*, server, qname, timeout, loop):
        _ = (server, timeout, loop)
        return mapping.get(qname, ("ok", 5.0, "1.2.3.4"))

    return _probe


async def _call(server="9.9.9.9"):
    sem = asyncio.Semaphore(1)
    loop = asyncio.get_running_loop()
    return await vr.probe_resolver(
        server=server,
        probes=("google.com",),
        canaries=("bad.example",),
        random_domains=("deadbeef.com",),
        timeout=2.0,
        loop=loop,
        sem=sem,
    )


def test_probe_resolver_filtering(monkeypatch):
    monkeypatch.setattr(
        vr,
        "probe_one",
        _fake_probe({"bad.example": ("nxdomain", None, None), "deadbeef.com": ("nxdomain", None, None)}),
    )
    _, verdict, _ = _run(_call())
    assert verdict == "filtering"


def test_probe_resolver_hijack(monkeypatch):
    monkeypatch.setattr(vr, "probe_one", _fake_probe({"deadbeef.com": ("ok", 4.0, "9.9.9.9")}))
    _, verdict, _ = _run(_call())
    assert verdict == "hijack"


def test_probe_resolver_gate1_failure(monkeypatch):
    monkeypatch.setattr(vr, "probe_one", _fake_probe({"google.com": ("timeout", None, None)}))
    _, verdict, _ = _run(_call())
    assert verdict == "timeout"


def test_probe_resolver_clean(monkeypatch):
    monkeypatch.setattr(vr, "probe_one", _fake_probe({"deadbeef.com": ("nxdomain", None, None)}))
    _, verdict, _ = _run(_call())
    assert verdict == "ok"


def test_fetch_canaries_returns_empty_on_error(monkeypatch):
    def _boom(url, timeout):
        del url, timeout
        raise OSError("network down")

    monkeypatch.setattr(vr, "_http_get", _boom)

    async def _go():
        loop = asyncio.get_running_loop()
        return await vr.fetch_canaries(url="http://x", timeout=1.0, loop=loop)

    assert asyncio.run(_go()) == []


def test_select_live_canaries_keeps_only_control_confirmed(monkeypatch):
    live = {"live-a.example", "live-b.example"}

    async def _probe(*, server, qname, timeout, loop):
        _ = (server, timeout, loop)
        if qname in live:
            return "ok", 3.0, "1.2.3.4"
        return "nxdomain", None, None

    monkeypatch.setattr(vr, "probe_one", _probe)

    async def _go():
        loop = asyncio.get_running_loop()
        return await vr.select_live_canaries(
            candidates=["dead.example", "live-a.example", "live-b.example"],
            control=("1.1.1.1",),
            timeout=2.0,
            loop=loop,
            n=3,
            max_scan=60,
        )

    out = asyncio.run(_go())
    assert out == ["live-a.example", "live-b.example"]


def test_select_live_canaries_caps_at_n(monkeypatch):
    async def _probe(*, server, qname, timeout, loop):
        _ = (server, qname, timeout, loop)
        return "ok", 3.0, "1.2.3.4"

    monkeypatch.setattr(vr, "probe_one", _probe)

    async def _go():
        loop = asyncio.get_running_loop()
        return await vr.select_live_canaries(
            candidates=["a.example", "b.example", "c.example", "d.example"],
            control=("1.1.1.1",),
            timeout=2.0,
            loop=loop,
            n=2,
            max_scan=60,
        )

    assert len(asyncio.run(_go())) == 2


def test_is_denylisted_host_exact_and_subdomain():
    assert is_denylisted_host(host="github.com") is True
    assert is_denylisted_host(host="codeload.github.com") is True
    assert is_denylisted_host(host="raw.githubusercontent.com") is True


def test_is_denylisted_host_no_overmatch():
    assert is_denylisted_host(host="evilgithub.com") is False
    assert is_denylisted_host(host="realbadspam.example") is False


def test_parse_feed_drops_denylisted_platforms():
    feed = (
        "http://codeload.github.com/payload.zip\n"
        "https://raw.githubusercontent.com/u/r/x.exe\n"
        "http://realbadspam.example/c2\n"
    )
    assert parse_feed(text=feed) == ["realbadspam.example"]
