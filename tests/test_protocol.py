"""Protocol tests, anchored on captured traffic and vendor-app ground truth.

The fixtures here are real bytes, not invented ones:

* ``APP_REQUEST`` is the exact frame the vendor app wrote to c304, captured on
  both iOS and macOS.
* ``CELLS_PAYLOAD`` / ``CELLS_GROUND_TRUTH`` are a type-0x05 payload and the 16
  cell voltages the app displayed for the same battery at the same second
  (1417607SLKOPGG08051 @ 2026-07-31 23:34:41).
"""

from __future__ import annotations

import pytest

from tensite_bms_ble.protocol import (
    build_request,
    crc16_arc,
    decode_cells,
    format_position,
    parse_frames,
)

MASTER_SERIAL = "1417725SLKOPGG08146"

APP_REQUEST = bytes.fromhex(
    "5e500131343137373235534c4b4f5047473038313436"
    "0207000001a0000000000000000014167e"
)

CELLS_PAYLOAD = bytes.fromhex(
    "ea41b74fb0a4a7d7c6f15f180528429e2e78afbe668f991246c2353d7208d094"
)
CELLS_GROUND_TRUTH = [
    3257, 3204, 3252, 3258, 3256, 3252, 3244, 3228,
    3259, 3259, 3254, 3248, 3231, 3258, 3253, 3256,
]


def _make_frame(
    msg_type: int,
    payload: bytes,
    serial: str = MASTER_SERIAL,
    proto: int = 0x10,
    position: int = 0x01A0,
    seq: int = 0,
) -> bytes:
    """Build a device->app frame the way the hardware does."""
    body = (
        bytes([proto, msg_type])
        + serial.encode("ascii")
        + b"\x02\x07"
        + b"\xff\xff"
        + position.to_bytes(2, "big")
        + seq.to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
        + len(payload).to_bytes(2, "big")
        + payload
    )
    return b"\x5e" + body + crc16_arc(body).to_bytes(2, "big") + b"\x7e"


class TestChecksum:
    def test_matches_app_request(self):
        """CRC-16/ARC over the body excluding the leading 0x5E."""
        assert crc16_arc(APP_REQUEST[1:-3]) == 0x1416

    def test_empty(self):
        assert crc16_arc(b"") == 0


class TestBuildRequest:
    def test_reproduces_app_bytes_exactly(self):
        assert build_request(MASTER_SERIAL) == APP_REQUEST

    def test_rejects_wrong_length_serial(self):
        with pytest.raises(ValueError, match="19 characters"):
            build_request("TOO-SHORT")

    def test_round_trips_through_parser(self):
        frames = parse_frames(bytearray(build_request(MASTER_SERIAL)))
        assert len(frames) == 1
        assert frames[0].serial == MASTER_SERIAL
        assert frames[0].proto == 0x50
        assert frames[0].position == 0x01A0
        assert frames[0].payload == b""


class TestDecodeCells:
    def test_matches_vendor_app_display(self):
        """All 16 values must match what the app showed at that second."""
        assert decode_cells(CELLS_PAYLOAD) == CELLS_GROUND_TRUTH

    def test_rejects_wrong_payload_size(self):
        with pytest.raises(ValueError, match="32-byte payload"):
            decode_cells(b"\x00" * 8)

    def test_values_are_plausible(self):
        assert all(2000 <= mv <= 3800 for mv in decode_cells(CELLS_PAYLOAD))


class TestParseFrames:
    def test_extracts_single_frame(self):
        buf = bytearray(_make_frame(0x05, CELLS_PAYLOAD))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert frames[0].msg_type == 0x05
        assert decode_cells(frames[0].payload) == CELLS_GROUND_TRUTH
        assert not buf, "fully consumed frames must leave nothing behind"

    def test_extracts_back_to_back_frames(self):
        buf = bytearray(
            _make_frame(0x05, CELLS_PAYLOAD, serial="1417607SLKOPGG08051")
            + _make_frame(0x01, bytes.fromhex("e6f8bbcbbc10ab6d"))
            + _make_frame(0x05, CELLS_PAYLOAD, serial="1417725SLKOPGG08099")
        )
        frames = parse_frames(buf)
        assert [f.msg_type for f in frames] == [0x05, 0x01, 0x05]
        assert frames[0].serial == "1417607SLKOPGG08051"
        assert frames[2].serial == "1417725SLKOPGG08099"

    def test_keeps_partial_frame_for_next_notification(self):
        """BLE splits frames across notifications; the tail must survive."""
        whole = _make_frame(0x05, CELLS_PAYLOAD)
        buf = bytearray(whole[:20])
        assert parse_frames(buf) == []
        assert len(buf) == 20, "incomplete frame must stay buffered"
        buf.extend(whole[20:])
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert decode_cells(frames[0].payload) == CELLS_GROUND_TRUTH

    def test_rejects_bad_crc(self):
        corrupt = bytearray(_make_frame(0x05, CELLS_PAYLOAD))
        corrupt[-3] ^= 0xFF  # damage the CRC
        assert parse_frames(corrupt) == []

    def test_resyncs_past_leading_garbage(self):
        buf = bytearray(b"\x5e\x5e\xff\x00" + _make_frame(0x05, CELLS_PAYLOAD))
        frames = parse_frames(buf)
        assert len(frames) == 1
        assert decode_cells(frames[0].payload) == CELLS_GROUND_TRUTH

    def test_survives_frame_markers_inside_payload(self):
        """0x5E and 0x7E are legal payload bytes; length+CRC drive framing."""
        payload = bytes([0x5E, 0x7E] * 16)
        frames = parse_frames(bytearray(_make_frame(0x05, payload)))
        assert len(frames) == 1
        assert frames[0].payload == payload

    def test_ignores_absurd_declared_length(self):
        buf = bytearray(_make_frame(0x05, CELLS_PAYLOAD))
        buf[34:36] = (9999).to_bytes(2, "big")
        assert parse_frames(buf) == []


class TestFormatPosition:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(0x01A0, "C01/PA0"), (0x0101, "C01/P01"), (0x0103, "C01/P03")],
    )
    def test_matches_app_labels(self, raw, expected):
        assert format_position(raw) == expected
