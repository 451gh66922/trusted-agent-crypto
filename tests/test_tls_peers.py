"""TlsClient ↔ MerchantServer state-machine integration."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.se import connect
from tacrypto.tls import (
    HandshakeState,
    MerchantServer,
    TlsClient,
    TlsError,
    complete_handshake,
)


def test_peers_handshake_exporters_and_app_data_without_se():
    suite = get_suite("intl")
    client = TlsClient(suite)
    server = MerchantServer(suite)
    complete_handshake(client, server)

    assert client.state == HandshakeState.CONNECTED
    assert server.state == HandshakeState.CONNECTED
    assert client.exporter_master_secret == server.exporter_master_secret
    assert client.channel_binding == server.channel_binding
    assert len(client.channel_binding) == 32

    ct = client.send_app_data(b'{"hello":"merchant"}')
    assert server.recv_app_data(ct) == b'{"hello":"merchant"}'
    st = server.send_app_data(b"ACK")
    assert client.recv_app_data(st) == b"ACK"


def test_peers_handshake_with_se_ecdh():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    client = TlsClient(suite, se=se)
    server = MerchantServer(suite)
    complete_handshake(client, server)
    assert client.channel_binding == server.channel_binding
    # GEN_KEY / ECDH / EXPORT appear in APDU transcript
    ins = {cmd[1] for cmd, _ in se.transcript}
    assert 0x46 in ins and 0x86 in ins and 0x88 in ins


def test_wrong_order_raises():
    suite = get_suite("intl")
    client = TlsClient(suite)
    try:
        client.send_app_data(b"nope")
        raise AssertionError
    except TlsError:
        pass


def test_exporter_label_api():
    suite = get_suite("intl")
    client = TlsClient(suite)
    server = MerchantServer(suite)
    complete_handshake(client, server)
    a = client.exporter("custom", b"ctx", 16)
    b = server.exporter("custom", b"ctx", 16)
    assert a == b and len(a) == 16
