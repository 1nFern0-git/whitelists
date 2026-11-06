"""Какой DNS-сервер спрашивает проба через интерфейс: без сети."""
import asyncio
import socket
import types

import pytest

from conftest import load

check_pairs = load("check_pairs_dns_server_mod", "check_pairs.py")


@pytest.fixture
def bound(monkeypatch):
    """Проба привязана к модему; сокеты DNS подменяются только в check_pairs
    (asyncio проверяет isinstance(…, socket.socket) и с глобальной подменой
    ломается)."""
    if not check_pairs.DNS_LIB:
        pytest.skip("нужен dnspython")
    monkeypatch.setattr(check_pairs, "BIND_INTERFACE", "wwan0")
    monkeypatch.setattr(check_pairs, "_NO_DNS_WARNED", False, raising=False)
    monkeypatch.setattr(check_pairs, "bind_device", lambda sock: None)
    sent = []

    class Udp:
        def __init__(self, *args, **kwargs):
            pass

        def settimeout(self, value):
            pass

        def sendto(self, data, address):
            sent.append(address)

        def recvfrom(self, size):
            raise socket.timeout("timed out")

        def close(self):
            pass

    fake = types.ModuleType("socket")
    fake.__dict__.update(vars(socket))
    fake.socket = Udp
    monkeypatch.setattr(check_pairs, "socket", fake)
    return monkeypatch, sent


def test_no_server_is_an_error_not_a_query_to_1111(bound):
    """Раньше без шлюза проба шла на 1.1.1.1: в режиме белого списка он закрыт,
    и каждая проба давала DNS_TIMEOUT — ложный «фильтр по именам»."""
    monkeypatch, sent = bound
    monkeypatch.setattr(check_pairs.plat, "interface_dns", lambda iface="": [])
    monkeypatch.setattr(check_pairs.plat, "interface_gateway", lambda iface="": None)
    result = asyncio.run(check_pairs.probe_dns("example.ru", [], 0.1))
    assert result["status"] == check_pairs.DNS_ERROR
    assert "--dns-probe-ns" in result["error"]
    assert sent == []


def test_probe_asks_interface_dns_before_gateway(bound):
    """resolvectl знает DNS модема (у PPP/QMI это не шлюз): проба спрашивает
    его — так же, как резолв через интерфейс, — а не шлюз."""
    monkeypatch, sent = bound
    monkeypatch.setattr(check_pairs.plat, "interface_dns", lambda iface="": ["10.0.0.53"])
    monkeypatch.setattr(check_pairs.plat, "interface_gateway", lambda iface="": "10.64.64.64")
    result = asyncio.run(check_pairs.probe_dns("example.ru", [], 0.1))
    assert result["resolver"] == "10.0.0.53"
    assert sent and all(address == ("10.0.0.53", 53) for address in sent)


def test_gateway_is_used_when_interface_dns_unknown(bound):
    """Без resolvectl (Windows, Docker, Alpine) — шлюз, как и раньше."""
    monkeypatch, sent = bound
    monkeypatch.setattr(check_pairs.plat, "interface_dns", lambda iface="": [])
    monkeypatch.setattr(check_pairs.plat, "interface_gateway", lambda iface="": "192.168.8.1")
    result = asyncio.run(check_pairs.probe_dns("example.ru", [], 0.1))
    assert result["resolver"] == "192.168.8.1"
    assert sent and all(address == ("192.168.8.1", 53) for address in sent)


def test_explicit_dns_probe_ns_wins(bound):
    monkeypatch, sent = bound
    monkeypatch.setattr(check_pairs.plat, "interface_dns", lambda iface="": ["10.0.0.53"])
    result = asyncio.run(check_pairs.probe_dns("example.ru", ["77.88.8.8"], 0.1))
    assert result["resolver"] == "77.88.8.8"
    assert all(address == ("77.88.8.8", 53) for address in sent)
