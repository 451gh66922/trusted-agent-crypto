"""Messages, transcript, simplified handshake, SE-ECDHE + Key Schedule."""

from __future__ import annotations

from tacrypto import get_suite
from tacrypto.se import SeError, connect
from tacrypto.tls import (
    ClientHello,
    ServerHello,
    TranscriptHash,
    run_simplified_handshake,
    tls_exporter,
    traffic_keys,
)
from tacrypto.tls.key_schedule import KeySchedule


def test_normalized_messages_are_deterministic():
    ch = ClientHello(random=b"\x11" * 32, key_share=b"\x22" * 32)
    sh = ServerHello(random=b"\x33" * 32, key_share=b"\x44" * 32)
    assert ch.encode()[0] == 1
    assert sh.encode()[0] == 2
    assert ch.encode() == ClientHello(random=b"\x11" * 32, key_share=b"\x22" * 32).encode()


def test_transcript_hash_order_matters():
    suite = get_suite("intl")
    a = TranscriptHash(suite)
    b = TranscriptHash(suite)
    m1, m2 = b"hello", b"world"
    a.update(m1)
    a.update(m2)
    b.update(m2)
    b.update(m1)
    assert a.digest() != b.digest()
    assert a.digest() == suite.hash(m1 + m2)


def test_simplified_handshake_exporters_match_without_se():
    suite = get_suite("intl")
    result, exp_c, exp_s = run_simplified_handshake(suite)
    assert exp_c == exp_s
    assert len(exp_c) == 32
    assert result.schedule.application.exporter_master_secret
    # Traffic keys usable with AES-GCM
    keys = result.traffic.application_server
    assert len(keys.key) == 16 and len(keys.iv) == 12
    ct = suite.aead_encrypt(keys.key, keys.iv, b"pay:100", aad=b"seq=0")
    assert suite.aead_decrypt(keys.key, keys.iv, ct, aad=b"seq=0") == b"pay:100"


def test_simplified_handshake_with_se_ecdh():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    result, exp_c, exp_s = run_simplified_handshake(suite, se=se)
    assert exp_c == exp_s

    # Ephemeral private key never appears in APDU transcript
    # (we don't know the sk bytes from Host — check EXPORT_SECRET response
    # is 32-byte shared secret, and GEN_KEY response starts with key_id)
    assert any(cmd[1] == 0x46 for cmd, _ in se.transcript)  # GEN_KEY
    assert any(cmd[1] == 0x86 for cmd, _ in se.transcript)  # ECDH
    assert any(cmd[1] == 0x88 for cmd, _ in se.transcript)  # EXPORT_SECRET

    # Re-derive exporter on a fresh KeySchedule with exported shared secret
    ks = KeySchedule(suite)
    ks.run(
        shared_secret=result.shared_secret,
        transcript_hash_hello=result.transcript_hash_hello,
        transcript_hash_server_finished=result.transcript_hash_server_finished,
        transcript_hash_client_finished=result.transcript_hash_client_finished,
    )
    assert ks.exporter_master_secret == result.exporter_master_secret
    assert (
        tls_exporter(suite, ks.exporter_master_secret, "ta demo", b"merchant-session", 32)
        == exp_c
    )


def test_export_secret_is_one_shot():
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    local = se.gen_ephemeral_key()
    peer = suite.generate_ephemeral_keypair()
    handle = se.ecdh(local.key_id, peer.public_key)
    secret = se.export_secret(handle)
    assert len(secret) == 32
    try:
        se.export_secret(handle)
        raise AssertionError("expected SeError after one-shot export")
    except SeError as exc:
        assert exc.sw == 0x6A88


def test_independent_peers_same_inputs_same_exporter():
    """Simulate SE-client Host and merchant Host running schedule separately."""
    suite = get_suite("intl")
    se = connect("intl")
    se.select()
    result, exp_c, exp_s = run_simplified_handshake(suite, se=se)
    assert exp_c == exp_s

    # Merchant side: only has shared secret + transcript hashes
    merchant = KeySchedule(suite)
    merchant.run(
        result.shared_secret,
        result.transcript_hash_hello,
        result.transcript_hash_server_finished,
        result.transcript_hash_client_finished,
    )
    assert merchant.exporter_master_secret == result.exporter_master_secret
    tk = traffic_keys(suite, merchant.server_application_traffic_secret)
    assert tk == result.traffic.application_server


def test_record_seal_open_with_sequence_nonce():
    from tacrypto.tls.record import nonce_for_sequence, open as rec_open, seal

    suite = get_suite("intl")
    result, exp_c, exp_s = run_simplified_handshake(suite)
    assert exp_c == exp_s
    keys = result.traffic.application_client
    assert nonce_for_sequence(keys.iv, 0) == keys.iv
    assert nonce_for_sequence(keys.iv, 1) != keys.iv
    blob = seal(suite, keys, b"hello", sequence=7, aad=b"aad")
    assert rec_open(suite, keys, blob, sequence=7, aad=b"aad") == b"hello"
