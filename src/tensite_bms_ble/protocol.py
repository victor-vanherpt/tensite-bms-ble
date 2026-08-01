"""The 5E..7E frame protocol: framing, checksum, and payload decoding.

Pure functions over bytes -- this module imports nothing Bluetooth-related and
is fully testable without hardware.

Frame layout, all offsets from the leading 0x5E::

    [0]      0x5E      start
    [1]      proto     0x10 device->app, 0x50 app->device
    [2]      msg_type
    [3:22]   serial    19 bytes ASCII
    [22:24]  protocol version (0x0207)
    [24:26]  direction
    [26:28]  cluster/position (0x01A0 = C01/PA0, the master)
    [28:30]  sequence   uint16 BE
    [30:34]  timestamp  uint32 BE
    [34:36]  pay_len    uint16 BE
    [36:]    payload    pay_len bytes
    [..]     CRC-16/ARC uint16 BE
    [..]     0x7E      end
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .const import (
    CELL_COUNT,
    FRAME_END,
    FRAME_START,
    HEADER_LEN,
    KEYSTREAM,
    MAX_PAYLOAD_LEN,
    POSITION_MASTER,
    PROTO_APP,
    PROTOCOL_VERSION,
    SERIAL_LENGTH,
    TYPE_KEYSTREAM,
)

__all__ = [
    "Frame",
    "build_request",
    "crc16_arc",
    "decode_cells",
    "format_position",
    "parse_frames",
]


def crc16_arc(data: bytes) -> int:
    """CRC-16/ARC: poly 0x8005 reflected (0xA001), init 0x0000, no final XOR.

    Computed over the frame body *excluding* the leading 0x5E, stored
    big-endian immediately before the trailing 0x7E.
    """
    reg = 0
    for byte in data:
        reg ^= byte
        for _ in range(8):
            reg = (reg >> 1) ^ 0xA001 if reg & 1 else reg >> 1
    return reg


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded frame off the notification stream."""

    proto: int
    msg_type: int
    serial: str
    position: int
    seq: int
    payload: bytes


def build_request(serial: str, position: int = POSITION_MASTER) -> bytes:
    """Build the vendor app's request frame verbatim.

    Message type 0x01, empty payload, zero sequence and timestamp. The app
    sends exactly one of these per session, addressed to the master's position.
    """
    if len(serial) != SERIAL_LENGTH:
        raise ValueError(
            f"serial must be {SERIAL_LENGTH} characters, got {len(serial)}: {serial!r}"
        )
    body = (
        bytes([PROTO_APP, TYPE_KEYSTREAM])
        + serial.encode("ascii")
        + struct.pack(">H", PROTOCOL_VERSION)
        + b"\x00\x00"  # direction: app -> device
        + struct.pack(">H", position)
        + b"\x00\x00"  # sequence
        + b"\x00\x00\x00\x00"  # timestamp
        + b"\x00\x00"  # payload length
    )
    return (
        bytes([FRAME_START])
        + body
        + struct.pack(">H", crc16_arc(body))
        + bytes([FRAME_END])
    )


def parse_frames(buf: bytearray) -> list[Frame]:
    """Pull every complete, CRC-valid frame out of *buf*, consuming it in place.

    Payloads legitimately contain 0x5E and 0x7E bytes, so framing is driven by
    the declared length and confirmed by the CRC. A candidate that fails
    validation is skipped and the scan resyncs on the next 0x5E; a trailing
    partial frame is left in the buffer for the next notification.

    Known gap: type 0x00 (30-byte payload) and the 77-byte variant of type 0x32
    carry a 3-byte trailer beginning 0xBD instead of the usual 2-byte CRC, and
    satisfy no CRC variant tried so far. They are dropped rather than guessed
    at. Every other type, including the cell frames, validates exactly.
    """
    frames: list[Frame] = []
    index = 0
    consumed = 0
    while True:
        index = buf.find(FRAME_START, index)
        if index < 0 or index + HEADER_LEN > len(buf):
            break
        pay_len = struct.unpack_from(">H", buf, index + 34)[0]
        if pay_len > MAX_PAYLOAD_LEN:
            index += 1
            continue
        total = HEADER_LEN + pay_len + 3  # + CRC(2) + END(1)
        if index + total > len(buf):
            break  # incomplete -- wait for more data
        body = bytes(buf[index + 1 : index + HEADER_LEN + pay_len])
        crc = struct.unpack_from(">H", buf, index + HEADER_LEN + pay_len)[0]
        if buf[index + total - 1] != FRAME_END or crc16_arc(body) != crc:
            index += 1
            continue
        frames.append(
            Frame(
                proto=buf[index + 1],
                msg_type=buf[index + 2],
                serial=bytes(buf[index + 3 : index + 22]).decode("ascii", "replace"),
                position=struct.unpack_from(">H", buf, index + 26)[0],
                seq=struct.unpack_from(">H", buf, index + 28)[0],
                payload=bytes(buf[index + HEADER_LEN : index + HEADER_LEN + pay_len]),
            )
        )
        index += total
        consumed = index
    del buf[:consumed]
    return frames


def decode_cells(payload: bytes) -> list[int]:
    """Decode a type-0x05 payload into 16 cell voltages in millivolts."""
    expected = CELL_COUNT * 2
    if len(payload) != expected:
        raise ValueError(f"expected {expected}-byte payload, got {len(payload)}")
    plain = bytes(a ^ b for a, b in zip(payload, KEYSTREAM))
    return [struct.unpack_from(">H", plain, 2 * i)[0] for i in range(CELL_COUNT)]


def format_position(position: int) -> str:
    """Render a raw position word the way the vendor app labels it, e.g. C01/PA0."""
    return f"C{position >> 8:02d}/P{position & 0xFF:02X}"
