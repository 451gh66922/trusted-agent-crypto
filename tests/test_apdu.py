"""APDU encode/decode smoke tests."""

from tacrypto.se.apdu import CommandApdu, parse_command, parse_response


def test_case1_roundtrip():
    raw = CommandApdu(0x00, 0xA4, 0x04, 0x00).encode()
    assert raw == bytes.fromhex("00A40400")
    cmd = parse_command(raw)
    assert cmd.data == b"" and cmd.le is None


def test_case3_with_data():
    raw = CommandApdu(0x80, 0x2A, 0x9E, 0x9A, data=b"\x01\x02").encode()
    cmd = parse_command(raw)
    assert cmd.data == b"\x01\x02"
    assert cmd.le is None


def test_response_sw():
    rsp = parse_response(b"hello\x90\x00")
    assert rsp.ok and rsp.data == b"hello"
