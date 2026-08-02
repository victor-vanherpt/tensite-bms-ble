"""Relay (0x02) and switch (0x03) frame tests.

Both frames share one parser in the vendor app -- ``RTRelay`` and ``RTSwitch``
are byte-identical classes deduplicated into the same machine code -- so one
decoder covers both. The fixtures here are the *masked* payloads exactly as
they came off the wire in the iOS capture, so the XOR path is exercised too.
"""

from __future__ import annotations

import pytest

from tensite_bms_ble.const import KEYSTREAM, MAX_ROUTES, ROUTE_ACTIVE
from tensite_bms_ble.models import BatteryReading
from tensite_bms_ble.protocol import decode_is_master, decode_routes

#: Masked bytes as captured. Keystream byte 0 is 0xE6.
RELAY_MASKED = bytes.fromhex("e7")  # -> 0x01
SWITCH_MASTER_MASKED = bytes.fromhex("19")  # -> 0xFF
SWITCH_SLAVE_MASKED = bytes.fromhex("e6")  # -> 0x00


def test_capture_fixtures_unmask_to_what_the_doc_records() -> None:
    """Guards the fixtures themselves against a keystream change."""
    assert RELAY_MASKED[0] ^ KEYSTREAM[0] == 0x01
    assert SWITCH_MASTER_MASKED[0] ^ KEYSTREAM[0] == 0xFF
    assert SWITCH_SLAVE_MASKED[0] ^ KEYSTREAM[0] == 0x00


def test_relay_matches_the_screenshot() -> None:
    """Ground truth: the master's Relay tab highlights route 1 alone.

    Screenshot IMG_0430 (2026-07-31 10:35:06, battery ...08146) shows route 1
    highlighted and routes 2-4 not, while the relay frame in the capture
    covering that moment reads 0x01.
    """
    assert decode_routes(RELAY_MASKED) == (1, 0, 0, 0)


def test_switch_master_is_all_threes() -> None:
    """And the master's Switching-value tab highlights nothing (IMG_0431)."""
    assert decode_routes(SWITCH_MASTER_MASKED) == (3, 3, 3, 3)


def test_switch_slave_is_all_zeroes() -> None:
    assert decode_routes(SWITCH_SLAVE_MASKED) == (0, 0, 0, 0)


def test_switch_frame_still_identifies_the_master() -> None:
    assert decode_is_master(SWITCH_MASTER_MASKED) is True
    assert decode_is_master(SWITCH_SLAVE_MASKED) is False


def test_one_byte_yields_exactly_four_routes() -> None:
    """The app draws ByteCount*4 routes, not a fixed sixteen."""
    assert len(decode_routes(RELAY_MASKED)) == 4


def test_routes_are_little_end_first_within_a_byte() -> None:
    """Route 1 is bits 0-1, route 4 is bits 6-7."""
    masked = bytes([0b11_10_01_00 ^ KEYSTREAM[0]])
    assert decode_routes(masked) == (0, 1, 2, 3)


def test_four_bytes_give_all_sixteen_routes() -> None:
    plain = bytes([0b01_01_01_01] * 4)
    masked = bytes(a ^ b for a, b in zip(plain, KEYSTREAM, strict=False))
    assert decode_routes(masked) == (1,) * MAX_ROUTES


def test_never_reports_more_than_sixteen_routes() -> None:
    plain = bytes([0xFF] * 8)
    masked = bytes(a ^ b for a, b in zip(plain, KEYSTREAM, strict=False))
    assert len(decode_routes(masked)) == MAX_ROUTES


def test_empty_payload_is_not_an_error() -> None:
    assert decode_routes(b"") == ()


@pytest.mark.parametrize("value", [0, 1, 2, 3])
def test_every_two_bit_value_survives_the_round_trip(value: int) -> None:
    masked = bytes([value ^ KEYSTREAM[0]])
    assert decode_routes(masked)[0] == value


class TestBatteryReading:
    def test_active_relays_follows_the_highlighted_value(self) -> None:
        battery = BatteryReading(
            serial="X", position=0x01A0, relay_routes=(1, 0, 0, 0)
        )
        assert battery.active_relays == (True, False, False, False)

    def test_switch_threes_are_not_reported_as_active(self) -> None:
        """3 renders unhighlighted in the app, so it is not "on" here either."""
        battery = BatteryReading(
            serial="X", position=0x01A0, relay_routes=(3, 3, 3, 3)
        )
        assert battery.active_relays == (False,) * 4
        assert ROUTE_ACTIVE == 1

    def test_absent_frames_leave_routes_empty(self) -> None:
        battery = BatteryReading(serial="X", position=0x01A0)
        assert battery.relay_routes == ()
        assert battery.switch_routes == ()
        assert battery.active_relays == ()
