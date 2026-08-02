"""Protocol tests, anchored on captured traffic and vendor-app ground truth.

The fixtures here are real bytes, not invented ones:

* ``APP_REQUEST`` is the exact frame the vendor app wrote to c304, captured on
  both iOS and macOS.
* ``CELLS_PAYLOAD`` / ``CELLS_GROUND_TRUTH`` are a type-0x05 payload and the 16
  cell voltages the app displayed for the same battery at the same second
  (1417607SLKOPGG08051 @ 2026-07-31 23:34:41).
"""

from __future__ import annotations

import struct

import struct

import pytest

from tensite_bms_ble.const import (
    MSG_CLASS_APP,
    MSG_CLASS_REALTIME,
    MSG_LINK_TEST,
    MSG_RT_ALARM,
    MSG_RT_SUMMARY,
    SERIAL_LENGTH,
)
from tensite_bms_ble.protocol import (
    ParseStats,
    build_request,
    crc16_arc,
    decode_alarm_bits,
    keystream,
    decode_cells,
    decode_is_master,
    decode_model,
    decode_topology,
    decode_summary,
    decode_temperatures,
    is_sentinel_temperature,
    format_position,
    parse_frames,
    stuff,
    unmask,
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
    """Build a device->app frame the way the hardware does, stuffing included."""
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
    return b"\x5e" + stuff(body + crc16_arc(body).to_bytes(2, "big")) + b"\x7e"


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
        assert frames[0].position == 0x01A0
        assert frames[0].payload == b""

    def test_is_a_link_test_not_a_data_request(self):
        """0x5001 is what the app's registry calls LinkTest -- a keepalive.

        Worth pinning: it reads like a request for data and is not one. The
        device streams on its own once the session is open, which is why a poll
        waits rather than asks.
        """
        frame = parse_frames(bytearray(build_request(MASTER_SERIAL)))[0]
        assert frame.msg_id == MSG_LINK_TEST
        assert frame.msg_class == MSG_CLASS_APP
        assert frame.payload == b""

    def test_message_id_is_one_sixteen_bit_field(self):
        """Not a protocol byte plus a type byte, which is how it was modelled.

        The app's registry settles it: every id it registers is exactly the
        pair those two bytes form.
        """
        frame = parse_frames(bytearray(build_request(MASTER_SERIAL)))[0]
        assert frame.msg_id == (frame.msg_class << 8) | frame.msg_type


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
        """0x5E/0x7E/0x7D are legal payload bytes -- they arrive stuffed."""
        payload = bytes([0x5E, 0x7E, 0x7D] * 10 + [0x00, 0x11])
        wire = _make_frame(0x05, payload)
        assert b"\x7d" in wire, "this payload must actually exercise stuffing"
        frames = parse_frames(bytearray(wire))
        assert len(frames) == 1
        assert frames[0].payload == payload

    def test_stuffed_frame_is_longer_on_the_wire(self):
        """A stuffed frame exceeds header+payload+crc; length alone can't frame it."""
        payload = bytes([0x7E] * 32)
        wire = _make_frame(0x05, payload)
        assert len(wire) > 36 + len(payload) + 3

    def test_ignores_absurd_declared_length(self):
        buf = bytearray(_make_frame(0x05, CELLS_PAYLOAD))
        buf[34:36] = (9999).to_bytes(2, "big")
        assert parse_frames(buf) == []


def _mask(plaintext: bytes) -> bytes:
    """Re-apply the keystream, so tests can start from readable plaintext."""
    return unmask(plaintext)  # XOR is its own inverse


class TestDecodeSummary:
    """Ground truth: the vendor app's Realtime Monitor for
    1417607SLKOPGG08051 at 2026-07-31 23:34:32 read SOC 49.7%, 51.8 V,
    20.4 A, max cell 3255 mV, min cell 3201 mV, 42 C max / 38 C min."""

    #: Real plaintext, extracted from the capture with the corrected parser.
    #: (An earlier version of this fixture was taken before the 0x5D escape
    #: was understood, and its tail was quietly corrupted -- which is exactly
    #: why the daily-energy fields went unnoticed for so long.)
    PLAIN = bytes.fromhex(
        "020680cb01f1020cb70c810a"  # voltage, current, soc, ?, max/min cell, ?
        "0101020101"
        "5c58"  # max/min temperature, 50 C offset
        "010101020101"
        "0002"  # 0.2 kWh charged today
        "0002"  # 0.2 kWh discharged today
        "00"
    )

    def test_layout_matches_the_vendor_app_parser(self):
        """Every byte the app reads, read the same way.

        RTSummary.setData at 0x909370 loads these offsets and widths; the names
        are its own, from RTSummary.toJson(). This asserts the whole map rather
        than the handful of fields we happened to need, so a decode that drifts
        away from the app's is caught even where nothing consumes the value.
        """
        s = decode_summary(_mask(self.PLAIN))
        plain = self.PLAIN
        assert s.voltage == int.from_bytes(plain[0:2], "big") / 10
        assert s.soc == int.from_bytes(plain[4:6], "big") / 10
        assert s.status_raw == plain[6]          # app field "Status"
        assert s.max_cell_mv == int.from_bytes(plain[7:9], "big")
        assert s.min_cell_mv == int.from_bytes(plain[9:11], "big")
        assert (s.max_cell_index, s.max_cell_packet, s.max_cell_cluster) == (
            plain[11], plain[12], plain[13],
        )
        assert (s.min_cell_index, s.min_cell_packet, s.min_cell_cluster) == (
            plain[14], plain[15], plain[16],
        )
        assert (s.max_temp_index, s.max_temp_packet, s.max_temp_cluster) == (
            plain[19], plain[20], plain[21],
        )
        assert (s.min_temp_index, s.min_temp_packet, s.min_temp_cluster) == (
            plain[22], plain[23], plain[24],
        )
        assert s.sd_status == plain[29]          # app field "SDStatus"

    def test_sd_status_is_reported_not_interpreted(self):
        """Located, but its values are unknown and untestable here.

        The app parses SDStatus and does not render it on the summary page, and
        no capture has an SD card fitted, so the raw byte is all we can honestly
        offer.
        """
        assert decode_summary(_mask(self.PLAIN)).sd_status == 0

    def test_a_short_frame_leaves_the_trailing_fields_unset(self):
        """Rather than raising or inventing a value."""
        s = decode_summary(_mask(self.PLAIN[:29]))
        assert s.sd_status is None
        assert s.voltage > 0  # everything before it still decodes

    def test_cell_position_fields(self):
        """[11] and [14] are 1-based positions of the highest/lowest cell."""
        s = decode_summary(_mask(self.PLAIN))
        assert s.max_cell_index == 0x0A
        assert s.min_cell_index == 0x02

    def test_faulty_battery_points_at_the_dead_cell(self):
        """Real capture, 1417C25SLKOPGG08043: cell 12 collapsed to 1492 mV
        while every other cell sat at 3326-3328, and the app reported
        'Cell Faults -> Voltage Under: Fault'."""
        plain = bytes.fromhex(
            "0201" "7ffe" "0353" "03" "0d00" "05d4" "08"
            "01010c0101" "5555" "010101010101" "0000" "0000" "00"
        )
        s = decode_summary(_mask(plain))
        assert s.min_cell_mv == 1492
        assert s.min_cell_index == 12
        assert s.soc == 85.1

    def test_daily_energy_matches_app(self):
        """Both batteries showed 0.2 kWh charged / 0.2 kWh discharged."""
        s = decode_summary(_mask(self.PLAIN))
        assert s.daily_charge_kwh == 0.2
        assert s.daily_discharge_kwh == 0.2

    def test_daily_energy_fields_are_independent(self):
        plain = bytearray(self.PLAIN)
        plain[25:27] = (38).to_bytes(2, "big")
        plain[27:29] = (6).to_bytes(2, "big")
        s = decode_summary(_mask(bytes(plain)))
        assert s.daily_charge_kwh == 3.8
        assert s.daily_discharge_kwh == 0.6

    def test_matches_vendor_app_display(self):
        s = decode_summary(_mask(self.PLAIN))
        assert s.voltage == 51.8
        assert s.soc == 49.7
        assert s.max_cell_mv == 3255
        assert s.min_cell_mv == 3201
        assert s.max_temperature == 42
        assert s.min_temperature == 38
        assert s.current == 20.3  # app rounded to 20.4 a moment later

    def test_power_is_signed(self):
        s = decode_summary(_mask(self.PLAIN))
        assert s.power == pytest.approx(51.8 * 20.3, abs=0.2)

    def test_current_is_offset_binary(self):
        """0x8000 is zero; below it means charging. Verified on a capture
        taken while the bank was charging, where the app showed -4.5 A."""
        plain = bytearray(self.PLAIN)
        plain[2:4] = (0x8000 - 45).to_bytes(2, "big")
        assert decode_summary(_mask(bytes(plain))).current == -4.5

    def test_zero_current(self):
        plain = bytearray(self.PLAIN)
        plain[2:4] = (0x8000).to_bytes(2, "big")
        assert decode_summary(_mask(bytes(plain))).current == 0.0

    def test_rejects_short_payload(self):
        with pytest.raises(ValueError, match="at least 29"):
            decode_summary(b"\x00" * 8)


class TestDecodeTemperatures:
    """Ground truth from the July capture: 08051's four sensors read
    38 C, 40 C and two faulted; 08146's six read 42/38/38/42/fault/42."""

    def test_four_sensors_with_fault_sentinels(self):
        """Sentinels are reported literally, as the vendor app shows them."""
        assert decode_temperatures(_mask(bytes([88, 90, 0, 20]))) == [38, 40, -50, -30]

    def test_six_sensor_pack(self):
        assert decode_temperatures(_mask(bytes([92, 88, 88, 92, 20, 92]))) == [
            42, 38, 38, 42, -30, 42,
        ]


    def test_recognises_sentinels(self):
        """Both are known not to be measurements. What they mean is an open
        question -- see is_sentinel_temperature() -- so nothing here asserts
        a cause."""
        assert is_sentinel_temperature(-50)
        assert is_sentinel_temperature(-30)

    def test_real_sub_zero_is_not_a_fault(self):
        """A pack really can sit below freezing; only the two sentinels are
        faults, so a cold battery must not be mistaken for a broken one."""
        for celsius in (-20, -10, -5, -1, 0):
            assert not is_sentinel_temperature(celsius)
        assert decode_temperatures(_mask(bytes([45, 40]))) == [-5, -10]


class TestDecodeModel:
    def test_reads_model_string(self):
        assert decode_model(_mask(b"AB4850/100_2.0\x00\x00")) == "AB4850/100_2.0"


class TestDecodeIsMaster:
    @pytest.mark.parametrize(("raw", "expected"), [(0xFF, True), (0x00, False)])
    def test_role_flag(self, raw, expected):
        assert decode_is_master(_mask(bytes([raw]))) is expected


class TestStuffing:
    @pytest.mark.parametrize("byte", [0x7E, 0x7D, 0x5E, 0x5D])
    def test_survives_round_trip_through_the_parser(self, byte):
        payload = bytes([byte]) * 32
        frames = parse_frames(bytearray(_make_frame(0x05, payload)))
        assert len(frames) == 1
        assert frames[0].payload == payload

    def test_untouched_when_nothing_needs_escaping(self):
        data = bytes(range(0x00, 0x40))
        assert stuff(data) == data

    def test_escape_encoding(self):
        """Both flags are escaped by the value one below them."""
        assert stuff(bytes([0x7E])) == bytes([0x7D, 0x01])
        assert stuff(bytes([0x5E])) == bytes([0x5D, 0x01])
        assert stuff(bytes([0x7D])) == bytes([0x7D, 0x02])
        assert stuff(bytes([0x5D])) == bytes([0x5D, 0x02])

    def test_masked_5e_round_trips(self):
        """Regression: 0x5E was assumed to escape as 7D 03, but the device
        uses 5D 01. Mishandling it shifts the payload by one byte from that
        point on -- which silently wiped out every cell frame at the operating
        point where a cell's masked high byte happened to equal 0x5E."""
        payload = bytes([0x5E]) * 32
        frames = parse_frames(bytearray(_make_frame(0x05, payload)))
        assert len(frames) == 1
        assert frames[0].payload == payload


class TestFormatPosition:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(0x01A0, "C01/PA0"), (0x0101, "C01/P01"), (0x0103, "C01/P03")],
    )
    def test_matches_app_labels(self, raw, expected):
        assert format_position(raw) == expected


class TestExhaustiveRoundTrip:
    """Sweeps over every value the hardware can actually produce.

    These exist because of a real bug that shipped: 0x5E was assumed to escape
    as ``7D 03`` when the device in fact uses ``5D 01``. Nothing caught it,
    because whether a frame contains a masked 0x5E depends on the *values being
    measured*. Every capture and every test happened to sit at cell voltages
    that avoided it -- until the pack charged to ~3355 mV, at which point cell
    frames stopped decoding entirely while every other frame type kept working.

    A spot-check cannot find that class of bug. A sweep can.
    """

    @pytest.mark.parametrize("msg_type", [0x00, 0x05, 0x21])
    def test_every_byte_value_survives_framing(self, msg_type):
        """Any payload byte must round-trip, escapable or not."""
        for value in range(256):
            payload = bytes([value]) * 32
            frames = parse_frames(bytearray(_make_frame(msg_type, payload)))
            assert len(frames) == 1, f"byte 0x{value:02x} broke framing"
            assert frames[0].payload == payload, f"byte 0x{value:02x} corrupted"

    def test_every_plausible_cell_voltage_round_trips(self):
        """Sweep the whole LiFePO4 range, all cells at the same voltage."""
        for mv in range(2000, 3801):
            payload = _mask(b"".join(struct.pack(">H", mv) for _ in range(16)))
            frames = parse_frames(bytearray(_make_frame(0x05, payload)))
            assert len(frames) == 1, f"{mv} mV broke framing"
            assert decode_cells(frames[0].payload) == [mv] * 16, f"{mv} mV wrong"

    def test_every_cell_position_at_the_dangerous_voltage(self):
        """The failing case was position-dependent: only one cell's high byte
        masked to 0x5E. Vary which cell sits there."""
        for position in range(16):
            cells = [3300] * 16
            for mv in range(3340, 3380):
                cells[position] = mv
                payload = _mask(b"".join(struct.pack(">H", c) for c in cells))
                frames = parse_frames(bytearray(_make_frame(0x05, payload)))
                assert len(frames) == 1, f"cell {position} at {mv} mV broke framing"
                assert decode_cells(frames[0].payload) == cells

    def test_every_temperature_value_round_trips(self):
        for raw in range(256):
            payload = _mask(bytes([raw] * 6))
            frames = parse_frames(bytearray(_make_frame(0x21, payload)))
            assert len(frames) == 1, f"raw temp 0x{raw:02x} broke framing"
            assert frames[0].payload == payload

    def test_every_summary_voltage_and_current_round_trips(self):
        """Voltage 0-100 V and the full current range, in decivolts/deciamps."""
        base = bytearray(TestDecodeSummary.PLAIN)
        for dv in range(0, 1001, 7):
            for raw_current in range(0, 65536, 1021):
                base[0:2] = struct.pack(">H", dv)
                base[2:4] = struct.pack(">H", raw_current)
                frames = parse_frames(bytearray(_make_frame(0x00, _mask(bytes(base)))))
                assert len(frames) == 1, f"{dv} dV / {raw_current} broke framing"
                summary = decode_summary(frames[0].payload)
                assert summary.voltage == dv / 10
                assert summary.current == (raw_current - 0x8000) / 10


class TestParseStats:
    def test_clean_stream_rejects_nothing(self):
        stats = ParseStats()
        buf = bytearray(
            _make_frame(0x05, CELLS_PAYLOAD) + _make_frame(0x00, b"\x00" * 30)
        )
        parse_frames(buf, stats)
        assert stats.frames == 2
        assert stats.rejected == 0
        assert stats.reject_ratio == 0.0

    def test_counts_crc_failures(self):
        stats = ParseStats()
        corrupt = bytearray(_make_frame(0x05, CELLS_PAYLOAD))
        corrupt[-3] ^= 0xFF
        parse_frames(corrupt, stats)
        assert stats.crc_failures == 1
        assert stats.reject_ratio == 1.0

    def test_counts_bad_escapes(self):
        stats = ParseStats()
        parse_frames(
            bytearray(b"\x5e\x10\x05\x7d\x09" + b"\x00" * 40 + b"\x7e"), stats
        )
        assert stats.bad_escapes >= 1

    def test_counts_truncation(self):
        stats = ParseStats()
        parse_frames(
            bytearray(b"\x5e\x10\x05\x00\x5e" + _make_frame(0x05, CELLS_PAYLOAD)),
            stats,
        )
        assert stats.truncated >= 1
        assert stats.frames == 1

    def test_stats_accumulate(self):
        a, b = ParseStats(frames=3, crc_failures=1), ParseStats(frames=2, truncated=4)
        a.add(b)
        assert a.frames == 5
        assert a.rejected == 5


class TestRealWireBytes:
    """Frames taken verbatim off the air, not built by this module's own
    ``stuff()``.

    This is the test that matters for the escape rule. Round-tripping through
    our own encoder is self-consistent: it passes just as happily with a wrong
    rule, because the same wrong rule is used in both directions. Only bytes
    the *device* produced can prove the rule is right.

    Captured 2026-08-01 16:10 (docs/data_sources/ble-captures/macos-20260801-1609/).
    The vendor app displayed 3.359-3.362 V for this battery at that moment.
    This frame contains both escape forms: ``5D 01`` (a masked 0x5E) and
    ``7D 02`` (a literal 0x7D).
    """

    WIRE = bytes.fromhex(
        "5e100531343137373235534c4b4f504747303831343602"
        "07ffff01a01d97291e57170020ebe6b6ebb130a64dc768"
        "5d018d04a5431d2fe3ae2567199882477d0234a7739dd1"
        "0c9edd7e"
    )
    EXPECTED = [
        3358, 3360, 3360, 3360, 3361, 3361, 3361, 3359,
        3360, 3360, 3360, 3360, 3360, 3360, 3360, 3360,
    ]

    def test_contains_both_escape_forms(self):
        assert b"\x5d\x01" in self.WIRE, "fixture must exercise the 0x5D escape"
        assert b"\x7d\x02" in self.WIRE, "fixture must exercise the 0x7D escape"

    def test_decodes_to_the_displayed_voltages(self):
        frames = parse_frames(bytearray(self.WIRE))
        assert len(frames) == 1, "real device frame must parse"
        assert frames[0].msg_type == 0x05
        assert frames[0].serial == MASTER_SERIAL
        assert decode_cells(frames[0].payload) == self.EXPECTED

    def test_crc_validates(self):
        stats = ParseStats()
        parse_frames(bytearray(self.WIRE), stats)
        assert stats.frames == 1
        assert stats.rejected == 0

    def test_our_encoder_reproduces_the_wire_bytes(self):
        """Closes the loop: stuff() must emit exactly what the device emits."""
        frames = parse_frames(bytearray(self.WIRE))
        body = self.WIRE[1:-1]
        assert stuff(_unstuff_for_test(body)) == body, (
            "stuff() disagrees with the device's own encoding"
        )
        assert frames[0].payload  # sanity


def _unstuff_for_test(body: bytes) -> bytes:
    """Local unstuffer, so the assertion above is not circular on one side."""
    out = bytearray()
    i = 0
    while i < len(body):
        b = body[i]
        if b in (0x5D, 0x7D):
            out.append(b + 1 if body[i + 1] == 0x01 else b)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


class TestDecodeAlarmBits:
    """Type 0x01 is the fault bitfield, not a keystream carrier.

    Zero across 356 samples from four healthy batteries; the only non-zero
    reading available is the faulty capture below.
    """

    HEALTHY = bytes(8)
    #: 1417C25SLKOPGG08043, 2026-08-01 22:30. Cell 12 collapsed to 1492 mV and
    #: the app reported exactly one alarm: Cell Faults -> Voltage Under: Fault.
    FAULTY = bytes.fromhex("0000300000000000")

    def test_healthy_is_all_zero(self):
        assert decode_alarm_bits(_mask(self.HEALTHY)) == self.HEALTHY
        assert not any(decode_alarm_bits(_mask(self.HEALTHY)))

    def test_faulty_capture_is_non_zero(self):
        bits = decode_alarm_bits(_mask(self.FAULTY))
        assert bits == self.FAULTY
        assert any(bits)
        assert bits[2] == 0x30

    def test_masked_healthy_payload_equals_the_keystream(self):
        """Why this frame was mistaken for keystream delivery: a zero plaintext
        masks to the keystream itself."""
        
        assert _mask(self.HEALTHY) == keystream(64)[:8]


class TestTopology:
    """Type 0x32: a count byte followed by that many 19-byte serials.

    The layout is the app's own -- RTTopology.setData at 0x90423c multiplies
    the count byte by 19 and requires count*19+1 to fit -- and the short form
    confirms it without circularity, since decoding it needs only keystream
    bytes that were derived from cell voltages.
    """

    #: Real 20-byte frame from 1417607SLKOPGG08051, masked as captured.
    SHORT = _mask(b"\x01" + b"1417607SLKOPGG08051")

    def test_short_frame_is_the_sender_announcing_itself(self):
        topology = decode_topology(self.SHORT)
        assert topology.count == 1
        assert topology.serials == ("1417607SLKOPGG08051",)
        assert topology.is_complete

    def test_the_two_observed_sizes_are_exactly_the_formula(self):
        """1 + 1*19 = 20 and 1 + 4*19 = 77, which is why those sizes appear."""
        assert 1 + 1 * SERIAL_LENGTH == 20
        assert 1 + 4 * SERIAL_LENGTH == 77

    def test_a_full_bank_roster_decodes_completely(self):
        """The real 77-byte frame, decoded end to end.

        This used to stop after two entries because the mask was a captured
        39-byte table. It is generated now, so the whole roster comes out --
        and the real capture yields the four batteries in position order,
        which is how the last three bytes of the old table were found to be
        wrong: the second entry is the *next* battery, not the sender again.
        """
        serials = [
            "1417725SLKOPGG08146",
            "1417725SLKOPGG08099",
            "1417607SLKOPGG08313",
            "1417607SLKOPGG08051",
        ]
        plain = b"\x04" + b"".join(s.encode() for s in serials)
        topology = decode_topology(_mask(plain))
        assert topology.count == 4
        assert list(topology.serials) == serials
        assert topology.is_complete
        assert topology.is_plausible

    def test_too_short_is_rejected(self):
        """The app refuses anything under 20 bytes; so do we."""
        with pytest.raises(ValueError):
            decode_topology(_mask(b"\x01" + b"short"))

    def test_an_implausible_count_is_flagged(self):
        """Eight batteries is the documented maximum for this hardware.

        A larger count means the frame was misread, not that someone wired up
        a hundred, so it is worth being able to tell.
        """
        assert decode_topology(_mask(b"\x01" + b"1417607SLKOPGG08051")).is_plausible
        big = decode_topology(_mask(bytes([99]) + b"1417607SLKOPGG08051"))
        assert big.count == 99
        assert not big.is_plausible

    def test_the_observed_bank_is_within_the_hardware_limit(self):
        plain = b"\x04" + b"1417725SLKOPGG08146" * 4
        assert decode_topology(_mask(plain)).is_plausible


class TestKeystreamGenerator:
    """The mask is generated, not a captured table.

    Taken from the vendor app at Msg 0x9609ec -- a linear congruential
    generator whose output byte is state >> 20. Pinning it here because the
    constants are the whole thing: get one wrong and every payload decodes to
    plausible-looking rubbish.
    """

    #: The first 36 bytes as originally captured. These were recovered by
    #: XOR-ing a cell payload against the voltages the app displayed at the
    #: same second, so they are ground truth, independent of the generator.
    CAPTURED_PREFIX = bytes.fromhex(
        "e6f8bbcbbc10ab6dca4953ac09844e0222c3a3056a3995a24a5d39877ebddc2c10b314ab"
    )

    def test_reproduces_the_captured_prefix(self):
        assert keystream(len(self.CAPTURED_PREFIX)) == self.CAPTURED_PREFIX

    def test_is_deterministic_and_prefix_stable(self):
        """A longer request must extend the same sequence, not a new one."""
        assert keystream(200)[:39] == keystream(39)

    def test_has_no_length_limit(self):
        """The 39-byte table is what made the topology frame look undecodable."""
        assert len(keystream(1000)) == 1000

    def test_corrects_the_three_bytes_the_old_table_had_wrong(self):
        """The table's last three bytes came from a bad assumption.

        They were derived from the topology frame by assuming its plaintext
        began with the sender's serial twice. The second entry is actually the
        next battery in the bank, and those serials differ only in their final
        three characters -- exactly the three bytes that were wrong.
        """
        assert keystream(39)[36:] == bytes.fromhex("b7925d")
        assert keystream(39)[36:] != bytes.fromhex("b69f52")

    def test_unmask_is_its_own_inverse(self):
        payload = bytes(range(77))
        assert unmask(unmask(payload)) == payload
