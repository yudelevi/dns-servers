import ipaddress

from dns_servers.refresh import (
    collapsed,
    parse_address,
    select_candidates,
    sort_key,
    source_last_checked,
)


def record(ip: str, reliability: float = 1.0, checked_at: str | None = None) -> dict:
    return {"ip": ip, "reliability": reliability, "checked_at": checked_at}


def test_parse_address_rejects_junk():
    assert parse_address(text="not-an-ip") is None
    assert parse_address(text=" 8.8.8.8 ") == ipaddress.ip_address("8.8.8.8")


def test_select_drops_unreliable():
    assert select_candidates(records=[record("8.8.8.8", 1.0), record("1.1.1.1", 0.5)]) == ["8.8.8.8"]


def test_select_drops_private_and_reserved():
    records = [record("192.168.1.1"), record("127.0.0.1"), record("0.0.0.0"), record("9.9.9.9")]
    assert select_candidates(records=records) == ["9.9.9.9"]


def test_select_drops_ipv6_unless_asked():
    records = [record("2606:4700:4700::1111"), record("1.1.1.1")]
    assert select_candidates(records=records) == ["1.1.1.1"]
    assert select_candidates(records=records, include_ipv6=True) == ["1.1.1.1", "2606:4700:4700::1111"]


def test_select_deduplicates_and_sorts_numerically():
    records = [record("10.0.0.1"), record("9.9.9.9"), record("8.8.8.8"), record("9.9.9.9")]
    assert select_candidates(records=records) == ["8.8.8.8", "9.9.9.9"]
    assert sort_key("9.9.9.9") > sort_key("8.8.8.8")


def test_source_last_checked_takes_the_newest():
    records = [
        record("8.8.8.8", checked_at="2021-01-01T00:00:00Z"),
        record("9.9.9.9", checked_at="2023-08-17T22:06:41Z"),
    ]
    assert source_last_checked(records=records) == "2023-08-17T22:06:41Z"
    assert source_last_checked(records=[record("8.8.8.8")]) is None


def test_collapsed_fires_when_the_list_halves(tmp_path):
    path = tmp_path / "nameservers.txt"
    path.write_text("\n".join(f"9.9.9.{n}" for n in range(100)) + "\n")
    assert collapsed(healthy=["9.9.9.9"], path=path) is True
    assert collapsed(healthy=[f"9.9.9.{n}" for n in range(80)], path=path) is False


def test_collapsed_allows_first_run(tmp_path):
    assert collapsed(healthy=["9.9.9.9"], path=tmp_path / "missing.txt") is False
