"""In-process and transport-driven handshake helpers."""

from __future__ import annotations

from tacrypto.tls.client import TlsClient
from tacrypto.tls.server import MerchantServer
from tacrypto.tls.state import HandshakeState, TlsError
from tacrypto.tls.transport import Transport


def complete_handshake(client: TlsClient, server: MerchantServer) -> None:
    """Drive a full 1-RTT handshake by exchanging record bytes only (in-process)."""
    ch = client.start_handshake()
    sh = server.handle_client_hello(ch)
    client.handle_server_hello(sh)
    flight = server.build_server_flight()
    cf = client.handle_server_flight(flight)
    server.handle_client_finished(cf)
    if client.state != HandshakeState.CONNECTED or server.state != HandshakeState.CONNECTED:
        raise RuntimeError("handshake did not reach CONNECTED")
    if client.channel_binding != server.channel_binding:
        raise RuntimeError("channel binding mismatch after handshake")
    if client.exporter_master_secret != server.exporter_master_secret:
        raise RuntimeError("exporter_master_secret mismatch after handshake")


def handshake_over_transport(
    client: TlsClient,
    server: MerchantServer,
    client_tx: Transport,
    server_tx: Transport,
) -> None:
    """Full 1-RTT handshake where peers only exchange bytes via transports."""
    ch = client.start_handshake()
    client_tx.send(ch)
    sh = server.handle_client_hello(server_tx.recv())
    server_tx.send(sh)
    client.handle_server_hello(client_tx.recv())
    flight = server.build_server_flight()
    server_tx.send(flight)
    cf = client.handle_server_flight(client_tx.recv())
    client_tx.send(cf)
    server.handle_client_finished(server_tx.recv())
    if client.state != HandshakeState.CONNECTED or server.state != HandshakeState.CONNECTED:
        raise TlsError("handshake did not reach CONNECTED")
    if client.channel_binding != server.channel_binding:
        raise TlsError("channel binding mismatch")


def app_exchange(
    sender_peer: TlsClient | MerchantServer,
    receiver_peer: TlsClient | MerchantServer,
    sender_tx: Transport,
    receiver_tx: Transport,
    payload: bytes,
    *,
    padding: int = 0,
) -> bytes:
    """Send one framed application record over the transport; return plaintext."""
    wire = sender_peer.send_app_data(payload, padding=padding)
    sender_tx.send(wire)
    return receiver_peer.recv_app_data(receiver_tx.recv())
