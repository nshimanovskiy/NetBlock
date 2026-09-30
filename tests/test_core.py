import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netblock_core as c  # noqa: E402


@pytest.mark.parametrize("raw,want", [
    ("example.com", "example.com"),
    ("https://WWW.Example.com/a?b=1", "example.com"),
    ("sub.example.co.uk:8080/x", "sub.example.co.uk"),
    ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ("bad_domain", None),
    ("-bad.com", None),
    ("", None),
])
def test_normalize_domain(raw, want):
    assert c.normalize_domain(raw) == want


@pytest.mark.parametrize("raw,want", [
    ("1.2.3.4", "1.2.3.4"),
    ("10.1.1.1/8", "10.0.0.0/8"),
    ("1.1.1.1-1.1.1.9", "1.1.1.1-1.1.1.9"),
    ("9.9.9.9-1.1.1.1", None),
    ("2001:db8::1", "2001:db8::1"),
    ("300.1.1.1", None),
    ("abc", None),
])
def test_normalize_ip(raw, want):
    assert c.normalize_ip(raw) == want


def test_expand_ipv4():
    nets, skipped = c.expand_ipv4(["1.1.1.1", "1.1.1.1", "10.0.0.0/8", "1.1.1.1-1.1.1.9",
                                   "2001:db8::1", "0.0.0.0/0"])
    names = [str(n) for n in nets]
    assert names.count("1.1.1.1/32") == 1
    assert "10.0.0.0/8" in names and "1.1.1.2/31" in names
    assert skipped == ["0.0.0.0/0"]  # слишком широкая сеть пропущена
    assert not any(":" in n for n in names)  # IPv6 не попадает в маршруты


def test_hosts_roundtrip(tmp_path):
    h = str(tmp_path / "hosts")
    original = "127.0.0.1 localhost\n"
    open(h, "w").write(original)
    assert c.hosts_in_sync([], h)
    c.apply_hosts(["a.com", "b.org"], h)
    text = open(h).read()
    assert "0.0.0.0 www.a.com" in text and text.startswith(original)
    assert c.hosts_in_sync(["a.com", "b.org"], h)
    assert not c.hosts_in_sync(["a.com"], h)
    open(h, "w").write(original)  # «кто-то стёр блок»
    assert not c.hosts_in_sync(["a.com"], h)
    c.apply_hosts(["a.com"], h)
    c.apply_hosts([], h)
    assert open(h).read() == original  # чужие записи не затронуты


def test_store_roundtrip(tmp_path):
    p = str(tmp_path / "list.json")
    s = c.Store(p)
    s.domains, s.ips, s.routes, s.enabled = ["a.com"], ["1.2.3.4"], ["1.2.3.4/32"], False
    s.save()
    s2 = c.Store(p)
    assert (s2.domains, s2.ips, s2.routes, s2.enabled) == (["a.com"], ["1.2.3.4"], ["1.2.3.4/32"], False)
