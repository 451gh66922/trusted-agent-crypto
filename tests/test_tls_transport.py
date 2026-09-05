"""TlsClient ↔ MerchantServer over independent transports + alerts."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.se import connect
from tacrypto.tls import (
    AlertDescription,
    HandshakeState,
    MemoryTransport,
    MerchantServer,
    RecordStream,
    TlsClient,
    app_exchange,
    complete_handshake,
    handshake_over_transport,
)


def test_memory_transport_handshake_and_app_data():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    client = TlsClient(suite, se=se)
    server = MerchantServer(suite)
    c_tx, s_tx = MemoryTransport.pair()
    handshake_over_transport(client, server, c_tx, s_tx)
    assert client.channel_binding == server.channel_binding
    pt = app_exchange(client, server, c_tx, s_tx, b'{"order":1}', padding=1)
    assert pt == b'{"order":1}'
    pt2 = app_exchange(server, client, s_tx, c_tx, b"ACK")
    assert pt2 == b"ACK"


def test_close_notify_alert():
    suite = get_suite("intl")
    client = TlsClient(suite)
    server = MerchantServer(suite)
    complete_handshake(client, server)
    wire = client.close()
    level, desc = server.handle_alert(wire)
    assert desc == AlertDescription.CLOSE_NOTIFY
    assert server.state == HandshakeState.CLOSED
    assert client.state == HandshakeState.CLOSED


def test_record_stream_buffers_partial_chunks():
    suite = get_suite("intl")
    client = TlsClient(suite)
    server = MerchantServer(suite)
    complete_handshake(client, server)
    wire = client.send_app_data(b"abcdef")
    stream = RecordStream(server.records)
    # Feed byte-by-byte to force buffering
    got = None
    for i in range(0, len(wire), 3):
        stream.feed(wire[i : i + 3])
        item = stream.try_read()
        if item is not None:
            got = item
            break
    assert got is not None
    ctype, content = got
    assert content == b"abcdef"
