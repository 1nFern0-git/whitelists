"""DNS-пробы через интерфейс: без сети, сокет DNS подменяется."""
import pytest

from conftest import load


def test_bound_dns_probes_run_in_parallel(monkeypatch):
    """DNS-проба через интерфейс делала блокирующий recvfrom прямо в корутине:
    при параллельности 6 пробы шли по одной, и 12 доменов без ответа DNS
    занимали 12 × таймаут вместо 2 × таймаут."""
    import asyncio
    import socket
    import time

    check_pairs = load("check_pairs_dns_mod", "check_pairs.py")
    if not check_pairs.DNS_LIB:
        pytest.skip("нужен dnspython")

    class SilentSocket:
        """UDP-сокет к DNS, который не отвечает: recvfrom ждёт таймаут."""
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def settimeout(self, value):
            self.timeout = value

        def sendto(self, data, address):
            pass

        def recvfrom(self, size):
            time.sleep(self.timeout)
            raise socket.timeout("timed out")

        def close(self):
            pass

    # Подменяется socket только внутри check_pairs: asyncio проверяет
    # isinstance(…, socket.socket) и с подменённым классом ломается.
    import types
    fake_socket = types.ModuleType("socket")
    fake_socket.__dict__.update(vars(socket))
    fake_socket.socket = SilentSocket
    monkeypatch.setattr(check_pairs, "socket", fake_socket)
    monkeypatch.setattr(check_pairs, "bind_device", lambda sock: None)
    monkeypatch.setattr(check_pairs, "BIND_INTERFACE", "modem0")
    timeout = 0.3

    async def scenario():
        started = time.perf_counter()
        results = await asyncio.gather(*(
            check_pairs.probe_dns(f"d{i}.ru", ["192.0.2.1"], timeout) for i in range(6)))
        return time.perf_counter() - started, results

    elapsed, results = asyncio.run(scenario())
    assert all(r["status"] == check_pairs.DNS_TIMEOUT for r in results)
    assert elapsed < timeout * 3, f"{elapsed:.2f} с — пробы идут последовательно"
