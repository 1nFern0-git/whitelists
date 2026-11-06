"""Разбор сетевых данных и кэша адресов: без сети и без реальной Windows."""
import json

import pytest

from conftest import load

plat = load("plat_mod", "platform_support.py")
check_domains = load("check_domains_cache_mod", "check-domains.py")

# Так выглядит ConvertTo-Json на машине с домашним Ethernet и телефоном-модемом
# рядом: маршрут по умолчанию идёт в Ethernet, модем ему не конкурент.
WINDOWS_PAYLOAD = {
    "adapters": [
        {"ifIndex": 10, "Name": "Ethernet",
         "InterfaceDescription": "Realtek PCIe GbE Family Controller", "Status": "Up"},
        {"ifIndex": 20, "Name": "vEthernet (Default Switch)",
         "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter", "Status": "Up"},
        {"ifIndex": 34, "Name": "Ethernet 3",
         "InterfaceDescription": "Remote NDIS based Internet Sharing Device",
         "Status": "Up"},
    ],
    "addresses": [
        {"InterfaceIndex": 10, "IPAddress": "192.168.1.94", "AddressFamily": "IPv4"},
        {"InterfaceIndex": 20, "IPAddress": "172.28.144.1", "AddressFamily": "IPv4"},
        {"InterfaceIndex": 34, "IPAddress": "192.168.42.129", "AddressFamily": "IPv4"},
        {"InterfaceIndex": 34, "IPAddress": "fe80::1", "AddressFamily": "IPv6"},
        {"InterfaceIndex": 34, "IPAddress": "2a00:1fa0::5", "AddressFamily": "IPv6"},
    ],
    "routes": [
        {"InterfaceIndex": 10, "NextHop": "192.168.1.1", "RouteMetric": 0},
        {"InterfaceIndex": 34, "NextHop": "192.168.42.129", "RouteMetric": 35},
    ],
}


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(plat, "IS_WINDOWS", True)
    monkeypatch.setattr(plat, "_NET_CACHE", None)
    monkeypatch.setattr(plat, "_run",
                        lambda command, timeout=5.0: json.dumps(WINDOWS_PAYLOAD))
    return plat


def test_address_family_as_number(monkeypatch):
    """Windows PowerShell 5.1 отдаёт AddressFamily числом: 2 — IPv4, 23 — IPv6."""
    payload = json.loads(json.dumps(WINDOWS_PAYLOAD))
    for item in payload["addresses"]:
        item["AddressFamily"] = 23 if ":" in item["IPAddress"] else 2
    monkeypatch.setattr(plat, "IS_WINDOWS", True)
    monkeypatch.setattr(plat, "_NET_CACHE", None)
    monkeypatch.setattr(plat, "_run", lambda command, timeout=5.0: json.dumps(payload))
    link = plat._windows_link("Ethernet 3")
    assert link["address"] == "192.168.42.129"
    assert link["address6"] == "2a00:1fa0::5"


def test_gateway_found_not_none(windows):
    """Раньше шлюз не находился ни в одной локали: ipconfig в cp866."""
    assert windows.interface_gateway() == "192.168.1.1"
    assert windows.interface_gateway("Ethernet 3") == "192.168.42.129"


def test_adapter_matched_exactly_not_by_substring(windows):
    """«Ethernet» не должен совпадать с «vEthernet (Default Switch)»."""
    assert windows.interface_address("Ethernet") == "192.168.1.94"
    assert windows.interface_address("vEthernet (Default Switch)") == "172.28.144.1"


def test_address_has_no_preferred_suffix(windows):
    """Get-NetIPAddress отдаёт чистый адрес, без «(Preferred)»."""
    address = windows.interface_address("Ethernet")
    assert address == "192.168.1.94"
    assert "(" not in address


def test_tethering_is_mobile_not_home_network(windows):
    """Телефон-модем — это мобильный канал, хотя адрес не CGNAT."""
    assert windows.interface_kind("Ethernet 3") == "mobile"
    assert windows.interface_kind("Ethernet") == "ethernet"
    assert windows.interface_kind("vEthernet (Default Switch)") == "unknown"
    assert windows.is_mobile_address("192.168.42.129") is False   # и всё же модем
    assert windows.usb_interfaces() == ["Ethernet 3"]


def test_default_route_is_the_one_with_gateway(windows):
    assert windows.default_route() == "Ethernet"


def test_bind_target_is_address_because_curl_cannot_resolve_names(windows):
    assert windows.bind_target("Ethernet 3") == "192.168.42.129"
    assert windows.interface_index("Ethernet 3") == 34


def test_link_local_ipv6_skipped(windows):
    link = next(item for item in windows.windows_network() if item["name"] == "Ethernet 3")
    assert link["address6"] == "2a00:1fa0::5"


def test_broken_powershell_output_is_not_fatal(monkeypatch):
    """Нет PowerShell или он вернул мусор — пустой список, но без падения."""
    monkeypatch.setattr(plat, "IS_WINDOWS", True)
    monkeypatch.setattr(plat, "_NET_CACHE", None)
    monkeypatch.setattr(plat, "_run", lambda command, timeout=5.0: "не json")
    assert plat.windows_network() == []
    assert plat.interface_gateway() is None
    assert plat.interface_kind("Ethernet") == "unknown"


# --- кэш адресов: общий + локальный слой ------------------------------------

def test_local_cache_layer_adds_addresses(tmp_path):
    base = tmp_path / "dns-cache.json"
    base.write_text(json.dumps({
        "generated_at": "2026-01-01T00:00:00Z",
        "domains": {"a.ru": {"A": ["1.1.1.1"], "AAAA": []}},
    }), encoding="utf-8")
    local = tmp_path / "dns-cache.local.json"
    local.write_text(json.dumps({
        "domains": {"a.ru": {"A": ["2.2.2.2"], "AAAA": ["::2"]},
                    "b.ru": {"A": ["3.3.3.3"], "AAAA": []}},
    }), encoding="utf-8")

    merged = check_domains.load_dns_cache(str(base), [str(local)])

    assert merged["a.ru"]["A"] == ["1.1.1.1", "2.2.2.2"]   # оба слоя
    assert merged["a.ru"]["AAAA"] == ["::2"]
    assert merged["b.ru"]["A"] == ["3.3.3.3"]              # только в локальном


def test_missing_local_layer_is_ignored(tmp_path):
    base = tmp_path / "dns-cache.json"
    base.write_text(json.dumps({"domains": {"a.ru": {"A": ["1.1.1.1"]}}}),
                    encoding="utf-8")
    merged = check_domains.load_dns_cache(str(base), [str(tmp_path / "нет.json")])
    assert merged == {"a.ru": {"A": ["1.1.1.1"]}}


def test_write_lines_uses_lf(tmp_path):
    """Список доменов для роутера не должен содержать \\r."""
    target = tmp_path / "list.txt"
    plat.write_lines(target, ["a.ru", "b.ru"])
    assert target.read_bytes() == b"a.ru\nb.ru\n"
