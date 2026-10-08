"""DNS pinning — HostResolver + PinnedNetworkBackend. DESIGN.md §10.5, §479.

Network'süz (CLAUDE.md §6): gerçek DNS/TCP'ye hiç gidilmez; `getaddrinfo` ve alttaki
NetworkBackend DI ile sahteleştirilir.
"""
import httpcore
import pytest

from pentestai.models import Actor, BudgetConfig, CapturedRequest, Scope
from pentestai.net.pinning import HostResolver, PinnedNetworkBackend, PinnedTransport
from pentestai.policy import Allow, Deny, PolicyEngine
from pentestai.scanner import Scanner


async def _fake_getaddrinfo(host: str, port):
    table = {
        "localhost": [(2, 1, 6, "", ("127.0.0.1", 0))],
        "Example.com": [(2, 1, 6, "", ("93.184.216.34", 0))],
    }
    if host not in table:
        raise OSError(f"çözülemedi: {host}")
    return table[host]


@pytest.mark.asyncio
async def test_resolve_all_maps_lowercased_host_to_first_ip():
    resolver = HostResolver(getaddrinfo=_fake_getaddrinfo)
    pin_map = await resolver.resolve_all(["localhost", "Example.com"])
    assert pin_map == {"localhost": "127.0.0.1", "example.com": "93.184.216.34"}


@pytest.mark.asyncio
async def test_resolve_all_skips_unresolvable_host():
    resolver = HostResolver(getaddrinfo=_fake_getaddrinfo)
    pin_map = await resolver.resolve_all(["localhost", "does-not-resolve.invalid"])
    assert pin_map == {"localhost": "127.0.0.1"}


class _FakeInnerBackend(httpcore.AsyncNetworkBackend):
    """Gerçek soket açmaz — yalnızca hangi (host, port) ile çağrıldığını kaydeder."""

    def __init__(self):
        self.calls: list[tuple[str, int]] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        return object()   # NetworkStream'i taklit etmeye gerek yok — bağlantı burada bitiyor


@pytest.mark.asyncio
async def test_pinned_backend_connects_to_pinned_ip_not_hostname():
    inner = _FakeInnerBackend()
    backend = PinnedNetworkBackend({"localhost": "127.0.0.1"}, inner=inner)
    await backend.connect_tcp("localhost", 3000)
    assert inner.calls == [("127.0.0.1", 3000)]


@pytest.mark.asyncio
async def test_pinned_backend_rejects_host_outside_pin_map():
    inner = _FakeInnerBackend()
    backend = PinnedNetworkBackend({"localhost": "127.0.0.1"}, inner=inner)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("evil.example", 80)
    assert inner.calls == []   # dış host'a hiç bağlanılmadı


@pytest.mark.asyncio
async def test_pinned_backend_lookup_is_case_insensitive():
    inner = _FakeInnerBackend()
    backend = PinnedNetworkBackend({"localhost": "127.0.0.1"}, inner=inner)
    await backend.connect_tcp("LocalHost", 3000)
    assert inner.calls == [("127.0.0.1", 3000)]


def test_pinned_transport_constructs_without_network_io():
    # Yalnızca httpcore.AsyncConnectionPool'un doğru network_backend ile kurulduğunu doğrular.
    transport = PinnedTransport({"localhost": "127.0.0.1"})
    assert isinstance(transport._pool._network_backend, PinnedNetworkBackend)


# --- Scope: external_network semantiği ---

def _authz(pin_map, external_network=False):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                 external_network=external_network)
    req = CapturedRequest(method="GET", url="http://localhost:3000/api/x")
    return PolicyEngine(scope, pin_map).authorize(req)


def test_public_ip_denied_by_default():
    d = _authz({"localhost": "93.184.216.34"})
    assert isinstance(d, Deny) and "ip" in d.reason


def test_public_ip_allowed_with_external_network_flag():
    d = _authz({"localhost": "93.184.216.34"}, external_network=True)
    assert isinstance(d, Allow)


def test_aws_imds_ipv6_always_denied_even_with_external_network():
    d = _authz({"localhost": "fd00:ec2::254"}, external_network=True)
    assert isinstance(d, Deny) and "ip" in d.reason


def test_ipv4_mapped_link_local_denied():
    d = _authz({"localhost": "::ffff:169.254.169.254"}, external_network=True)
    assert isinstance(d, Deny) and "ip" in d.reason


def test_multicast_and_unspecified_denied_even_with_external_network():
    assert isinstance(_authz({"localhost": "224.0.0.1"}, external_network=True), Deny)
    assert isinstance(_authz({"localhost": "0.0.0.0"}, external_network=True), Deny)


# --- Scanner.build_sessions entegrasyonu (DI resolver; ağa hiç çıkılmaz) ---

@pytest.mark.asyncio
async def test_build_sessions_pins_dns_and_binds_transport():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(
        "http://localhost:3000", scope, BudgetConfig(),
        resolver=HostResolver(getaddrinfo=_fake_getaddrinfo),
    )
    actor_pairs = [(Actor(name="a"), {"type": "static", "headers": {}, "cookies": {}})]
    sessions = await scanner.build_sessions(actor_pairs)

    assert scanner.policy.pin_map == {"localhost": "127.0.0.1"}
    assert isinstance(scanner.sessions._transport, PinnedTransport)
    assert sessions
    await scanner.aclose()
