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
    CURRENT_ZERO,
    ESCAPE_FLAG,
    ESCAPE_LITERAL,
    ESCAPE_PREFIXES,
    FRAME_END,
    FRAME_START,
    HEADER_LEN,
    KEYSTREAM,
    MAX_PAYLOAD_LEN,
    MAX_ROUTES,
    POSITION_MASTER,
    PROTO_APP,
    PROTOCOL_VERSION,
    ROUTES_PER_BYTE,
    SERIAL_LENGTH,
    TEMPERATURE_SENTINELS,
    TEMPERATURE_OFFSET,
    TYPE_KEYSTREAM,
)

__all__ = [
    "Frame",
    "ParseStats",
    "Summary",
    "build_request",
    "crc16_arc",
    "decode_alarm_bits",
    "decode_cells",
    "decode_is_master",
    "decode_routes",
    "decode_model",
    "decode_summary",
    "decode_temperatures",
    "is_sentinel_temperature",
    "format_position",
    "parse_frames",
    "unmask",
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


@dataclass(slots=True)
class ParseStats:
    """Running tally of what the parser rejected.

    Framing bugs in this protocol are silent by nature -- a mishandled escape
    yields a frame that still looks well-formed -- so the only early warning is
    the rate at which candidates get thrown away. A healthy stream rejects
    essentially nothing.
    """

    frames: int = 0
    #: Passed the length check but failed CRC. Corruption, or a decode bug.
    crc_failures: int = 0
    #: Declared length disagreed with the framing.
    length_mismatches: int = 0
    #: An escape prefix was followed by something that is not a valid code.
    bad_escapes: int = 0
    #: A frame start appeared before the previous frame terminated.
    truncated: int = 0

    @property
    def rejected(self) -> int:
        return (
            self.crc_failures
            + self.length_mismatches
            + self.bad_escapes
            + self.truncated
        )

    @property
    def reject_ratio(self) -> float:
        """Rejected candidates as a fraction of everything seen."""
        total = self.frames + self.rejected
        return self.rejected / total if total else 0.0

    def add(self, other: ParseStats) -> None:
        self.frames += other.frames
        self.crc_failures += other.crc_failures
        self.length_mismatches += other.length_mismatches
        self.bad_escapes += other.bad_escapes
        self.truncated += other.truncated


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded frame off the notification stream."""

    proto: int
    msg_type: int
    serial: str
    position: int
    seq: int
    payload: bytes

    @property
    def plaintext(self) -> bytes:
        """Payload with the XOR mask removed."""
        return unmask(self.payload)


def unmask(payload: bytes) -> bytes:
    """Strip the XOR keystream from a payload.

    Only the first ``len(KEYSTREAM)`` bytes can be recovered; anything beyond
    that is returned untouched, because how the keystream continues past byte
    38 is not yet known. In practice every decoded frame type is shorter than
    this.
    """
    n = min(len(payload), len(KEYSTREAM))
    return bytes(a ^ b for a, b in zip(payload[:n], KEYSTREAM)) + payload[n:]


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
        + stuff(body + struct.pack(">H", crc16_arc(body)))
        + bytes([FRAME_END])
    )


#: byte -> (prefix, code) for the four values that must be escaped.
_STUFF = {
    FRAME_END: (FRAME_END - 1, ESCAPE_FLAG),
    FRAME_START: (FRAME_START - 1, ESCAPE_FLAG),
    **{p: (p, ESCAPE_LITERAL) for p in ESCAPE_PREFIXES},
}


def stuff(data: bytes) -> bytes:
    """Apply the byte stuffing used between the frame delimiters.

    The app's captured request happens to contain no byte needing an escape,
    so this is invisible there -- but a serial or checksum that did contain one
    would corrupt the frame without it.
    """
    if not any(b in _STUFF for b in data):
        return data
    out = bytearray()
    for byte in data:
        escape = _STUFF.get(byte)
        if escape is None:
            out.append(byte)
        else:
            out += bytes(escape)
    return bytes(out)


def _unstuff(data: bytes) -> bytes | None:
    """Reverse the byte stuffing. None if a malformed escape appears."""
    if not any(b in ESCAPE_PREFIXES for b in data):
        return data
    out = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte not in ESCAPE_PREFIXES:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= len(data):
            return None
        code = data[i + 1]
        if code == ESCAPE_FLAG:
            out.append(byte + 1)
        elif code == ESCAPE_LITERAL:
            out.append(byte)
        else:
            return None
        i += 2
    return bytes(out)


def parse_frames(
    buf: bytearray, stats: ParseStats | None = None
) -> list[Frame]:
    """Pull every complete, valid frame out of *buf*, consuming it in place.

    Framing is HDLC-like: a frame runs from 0x5E to the next unescaped 0x7E,
    with both 0x7D and 0x5D acting as escape prefixes (see ``ESCAPE_PREFIXES``).
    Content is then confirmed by CRC-16/ARC; nothing is accepted unverified.

    Getting the stuffing wrong is expensive and quiet. A mishandled escape
    still yields a plausible-looking frame, just shifted by a byte from that
    point on, and whether a payload contains one depends on the values being
    reported -- so a whole message type can vanish at one operating point and
    be perfectly fine at another.
    """
    frames: list[Frame] = []
    index = 0
    consumed = 0
    while True:
        index = buf.find(FRAME_START, index)
        if index < 0:
            break
        end = _find_frame_end(buf, index + 1)
        if end == _TRUNCATED:
            if stats:
                stats.truncated += 1
            index += 1  # a new frame started before this one ended; resync
            continue
        if end is None:
            if len(buf) - index > MAX_PAYLOAD_LEN + 64:
                index += 1  # runaway: no terminator in sight, resync
                continue
            break  # incomplete -- wait for more data
        frame = _decode_frame(bytes(buf[index + 1 : end]), stats)
        if frame is None:
            index += 1
            continue
        if stats:
            stats.frames += 1
        frames.append(frame)
        index = end + 1
        consumed = index
    del buf[:consumed]
    return frames


#: Distinguishes "a new frame started before this one ended" (resync now) from
#: "no terminator yet" (wait for more bytes).
_TRUNCATED = -1


def _find_frame_end(buf: bytearray, start: int) -> int | None:
    """Index of the terminating 0x7E, skipping escaped bytes.

    Returns ``_TRUNCATED`` if another frame start appears first, or None if the
    buffer simply has not caught up yet.
    """
    i = start
    while i < len(buf):
        byte = buf[i]
        if byte == FRAME_END:
            return i
        if byte in ESCAPE_PREFIXES:
            i += 2  # the escaped byte cannot itself terminate the frame
            continue
        if byte == FRAME_START:
            return _TRUNCATED
        i += 1
    return None


def _decode_frame(raw: bytes, stats: ParseStats | None = None) -> Frame | None:
    """Validate and decode one frame body (between 0x5E and 0x7E, exclusive)."""
    body = _unstuff(raw)
    if body is None:
        if stats:
            stats.bad_escapes += 1
        return None
    if len(body) < HEADER_LEN:
        return None  # too short to be a candidate at all; not counted
    pay_len = struct.unpack_from(">H", body, 33)[0]
    if pay_len > MAX_PAYLOAD_LEN or len(body) != (HEADER_LEN - 1) + pay_len + 2:
        if stats:
            stats.length_mismatches += 1
        return None
    if crc16_arc(body[:-2]) != struct.unpack_from(">H", body, len(body) - 2)[0]:
        if stats:
            stats.crc_failures += 1
        return None

    payload_at = HEADER_LEN - 1
    return Frame(
        proto=body[0],
        msg_type=body[1],
        serial=body[1 + 1 : 1 + 20].decode("ascii", "replace"),
        position=struct.unpack_from(">H", body, 25)[0],
        seq=struct.unpack_from(">H", body, 27)[0],
        payload=body[payload_at : payload_at + pay_len],
    )


def decode_cells(payload: bytes) -> list[int]:
    """Decode a type-0x05 payload into 16 cell voltages in millivolts."""
    expected = CELL_COUNT * 2
    if len(payload) != expected:
        raise ValueError(f"expected {expected}-byte payload, got {len(payload)}")
    plain = unmask(payload)
    return [struct.unpack_from(">H", plain, 2 * i)[0] for i in range(CELL_COUNT)]


@dataclass(frozen=True, slots=True)
class Summary:
    """Pack-level telemetry from a type-0x00 frame.

    Field offsets were established by lining up captured frames against the
    vendor app's Realtime Monitor at the same second; voltage, SOC and both
    cell extremes match its display exactly.
    """

    voltage: float  # V
    current: float  # A, positive = discharging
    soc: float  # %
    max_cell_mv: int
    min_cell_mv: int
    #: 1-based positions of the strongest and weakest cell.
    max_cell_index: int
    min_cell_index: int
    max_temperature: int  # C
    min_temperature: int  # C
    daily_charge_kwh: float
    daily_discharge_kwh: float

    @property
    def power(self) -> float:
        """Signed power in watts, positive while discharging."""
        return round(self.voltage * self.current, 1)


def decode_summary(payload: bytes) -> Summary:
    """Decode a type-0x00 payload.

    Layout, after unmasking::

        [0:2]   uint16 BE  pack voltage      0.1 V
        [2:4]   uint16 BE  current           offset binary at 0x8000, 0.1 A
        [4:6]   uint16 BE  state of charge   0.1 %
        [6]                unknown, constant 0x02
        [7:9]   uint16 BE  highest cell      mV
        [9:11]  uint16 BE  lowest cell       mV
        [11]               unknown, varies
        [17]    uint8      highest pack temperature, 50 C offset
        [18]    uint8      lowest pack temperature, 50 C offset
        [25:27] uint16 BE  energy charged today       0.1 kWh
        [27:29] uint16 BE  energy discharged today    0.1 kWh

    The two cell-position bytes were pinned by pairing summary frames with the
    cell frames around them: whenever the extreme is unambiguous (the runner-up
    is more than 20 mV away) they identify the right cell in 198 of 198 and 20
    of 20 samples respectively. Below that margin they disagree occasionally,
    which is expected -- the two frame types are snapshots taken moments apart,
    so which cell is lowest can genuinely change between them.

    The daily counters were pinned by differencing two captures 17 hours
    apart: at 23:34 two batteries displayed 0.2 kWh / 0.2 kWh and both read
    ``00 02 00 02`` here; by 16:09 the next day, after a day of charging, the
    same fields had moved independently of each other.

    Bytes [6], [11]-[16], [19]-[24] and [29] are not decoded. They are mostly
    small constants (0x01 / 0x02) that look like per-category status enums,
    but every capture so far has the pack entirely fault-free, so there is
    nothing to correlate them against.
    """
    if len(payload) < 29:
        raise ValueError(f"expected at least 29 bytes, got {len(payload)}")
    plain = unmask(payload)
    return Summary(
        voltage=struct.unpack_from(">H", plain, 0)[0] / 10.0,
        current=(struct.unpack_from(">H", plain, 2)[0] - CURRENT_ZERO) / 10.0,
        soc=struct.unpack_from(">H", plain, 4)[0] / 10.0,
        max_cell_mv=struct.unpack_from(">H", plain, 7)[0],
        min_cell_mv=struct.unpack_from(">H", plain, 9)[0],
        max_cell_index=plain[11],
        min_cell_index=plain[14],
        max_temperature=plain[17] - TEMPERATURE_OFFSET,
        min_temperature=plain[18] - TEMPERATURE_OFFSET,
        daily_charge_kwh=struct.unpack_from(">H", plain, 25)[0] / 10.0,
        daily_discharge_kwh=struct.unpack_from(">H", plain, 27)[0] / 10.0,
    )


def decode_temperatures(payload: bytes) -> list[int]:
    """Decode a type-0x21 payload into per-sensor pack temperatures in C.

    One byte per sensor with a 50 degree offset; four or six sensors depending
    on the model. Values are returned exactly as the BMS reports them,
    including the -50 C / -30 C fault sentinels, which is what the vendor app
    displays. Use :func:`is_faulty_temperature` to recognise them.
    """
    return [raw - TEMPERATURE_OFFSET for raw in unmask(payload)]


def is_sentinel_temperature(celsius: int | None) -> bool:
    """Whether a decoded temperature is a sentinel rather than a measurement.

    -50 C and -30 C (raw 0x00 and 0x14) are the two values the BMS uses for a
    sensor position that is not returning a reading. **What they mean is
    deliberately not asserted.**

    The vendor app is no help, and that is now settled rather than assumed: its
    Dart code stores the bytes raw and applies the -50 offset only when drawing
    the page, with a null check for "no value" as the single special case. No
    comparison against 20, 30 or 50 exists anywhere in the binary, so the app
    prints -50 and -30 exactly as it prints 25. It does not know either.

    The capture evidence is ambiguous in the other direction:

    * -30 sits at position 5 on *both* six-sensor packs in every single sample,
      which looks like a position that model never fits.
    * -50 appears on 08051's positions 3 and 4 while the identical four-sensor
      08313 reports real temperatures there, which looks like a genuine fault.

    That points the opposite way to the intuitive reading, so no cause is
    claimed. Only the fact that neither is a temperature is treated as known.
    """
    return celsius in TEMPERATURE_SENTINELS



def decode_alarm_bits(payload: bytes) -> bytes:
    """Decode a type-0x01 payload into the raw fault bitfield.

    Eight bytes, all zero when the pack reports no faults -- verified across
    356 samples from four healthy batteries. The one faulty capture available
    (1417C25SLKOPGG08043, which the app showed as *Cell Faults -> Voltage
    Under: Fault*) reads ``00 00 30 00 00 00 00 00``.

    The field packs 29 alarms as 2-bit severities. Use
    :func:`~tensite_bms_ble.alarms.decode_alarms` to split it up; the layout was
    read out of the vendor app's own parser and is documented there. This
    function stays raw so the unmodified field can be logged.
    """
    return unmask(payload)


def decode_model(payload: bytes) -> str:
    """Decode a type-0x24 payload into the model string, e.g. AB4850/100_2.0."""
    return unmask(payload).split(b"\x00")[0].decode("ascii", "replace").strip()


def decode_routes(payload: bytes) -> tuple[int, ...]:
    """Decode a relay (0x02) or switch (0x03) payload into per-route values.

    Both frames share one parser in the vendor app -- ``RTRelay`` and
    ``RTSwitch`` are byte-identical classes, deduplicated into the same machine
    code -- and it is simply four 2-bit values per byte, low bits first, for up
    to sixteen routes. The model also keeps the payload length as ``ByteCount``,
    which is how the app decides how many routes to draw: one byte on this
    hardware, hence the four toggles on each tab.

    Each value is 0-3. Only one meaning is established, by pairing the iOS
    capture with the screenshot taken during it: the master's relay frame reads
    0x01, so route 1 is 1 and routes 2-4 are 0, and the app's Relay tab
    highlights route 1 alone. **1 is therefore the active state.** Both 0 and 3
    render unhighlighted -- the master's switch frame is 0xFF, every route 3,
    and its Switching-value tab highlights nothing -- so those two are not
    distinguished here and the raw value is passed through.

    Returns one entry per route actually present, so a one-byte payload gives
    four values rather than sixteen mostly-invented ones.
    """
    data = unmask(payload)[: MAX_ROUTES // ROUTES_PER_BYTE]
    return tuple(
        (byte >> shift) & 0b11
        for byte in data
        for shift in range(0, 8, 2)
    )


def decode_is_master(payload: bytes) -> bool:
    """Decode a type-0x03 payload: 0xFF on the bank master, 0x00 otherwise.

    This is the switch frame (see decode_routes()); the master reports every
    route as 3 and the others report 0. Kept as its own function because the
    master/slave distinction is what callers actually want from it, and because
    that behaviour is what 84 captured samples support -- not any claim about
    what a switch value of 3 means.
    """
    return bool(unmask(payload)[:1] == b"\xff")


def format_position(position: int) -> str:
    """Render a raw position word the way the vendor app labels it, e.g. C01/PA0."""
    return f"C{position >> 8:02d}/P{position & 0xFF:02X}"
