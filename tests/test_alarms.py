"""Alarm bitfield tests.

The layout under test was read out of the vendor app's own parser
(``RTAlarm.setData()``), so these tests mostly guard the transcription of that
table -- the failure mode that matters is an alarm silently landing one slot
off, which is exactly what an earlier hand-derived mapping got wrong.
"""

from __future__ import annotations

import pytest

from tensite_bms_ble.alarms import (
    ALARM_FIELD_LEN,
    ALARM_SLOTS,
    ALARM_SLOTS_BY_KEY,
    AlarmLevel,
    active_alarms,
    decode_alarms,
    unmapped_bits,
)
from tensite_bms_ble.models import BatteryReading

#: The only real fault ever captured: battery 1417C25SLKOPGG08043, for which
#: the vendor app displayed exactly "Cell Faults -> Voltage Under: Fault".
FAULTY_BITS = bytes.fromhex("0000300000000000")

HEALTHY_BITS = bytes(ALARM_FIELD_LEN)


def test_ground_truth_faulty_capture() -> None:
    """The one known fault must decode to the one alarm the app showed."""
    firing = active_alarms(FAULTY_BITS)
    assert len(firing) == 1
    slot, level = firing[0]
    assert slot.key == "CellVoltageUnder"
    assert slot.category == "Cell Faults"
    assert slot.label == "Voltage Under"
    assert level is AlarmLevel.LEVEL3


def test_ground_truth_does_not_trip_the_neighbours() -> None:
    """Guards the off-by-one that broke the first attempt at this table.

    ``CellVoltageOver`` and ``VoltageOver`` sit directly either side of
    ``CellVoltageUnder``; a uniform four-alarms-per-byte assumption lands on one
    of them instead.
    """
    levels = decode_alarms(FAULTY_BITS)
    assert levels["CellVoltageOver"] is AlarmLevel.NONE
    assert levels["VoltageOver"] is AlarmLevel.NONE
    assert levels["CellVoltageDiffExcess"] is AlarmLevel.NONE


def test_healthy_field_reports_nothing() -> None:
    assert active_alarms(HEALTHY_BITS) == ()
    assert set(decode_alarms(HEALTHY_BITS).values()) == {AlarmLevel.NONE}


def test_every_alarm_is_reported_even_when_clear() -> None:
    """A stable key set keeps entity sets from changing shape on recovery."""
    assert len(decode_alarms(HEALTHY_BITS)) == len(ALARM_SLOTS)
    assert len(decode_alarms(FAULTY_BITS)) == len(ALARM_SLOTS)


def test_slots_are_unique_and_do_not_overlap() -> None:
    """No two alarms may claim the same bit pair."""
    positions = [(slot.byte, slot.shift) for slot in ALARM_SLOTS]
    assert len(set(positions)) == len(positions)
    assert len(ALARM_SLOTS_BY_KEY) == len(ALARM_SLOTS)


def test_slots_stay_inside_the_field() -> None:
    for slot in ALARM_SLOTS:
        assert 0 <= slot.byte < ALARM_FIELD_LEN
        assert slot.shift in (0, 2, 4, 6)


def test_qualified_names_are_unique() -> None:
    """Charge and discharge share labels like "Temperature Over"."""
    assert len({slot.name for slot in ALARM_SLOTS}) == len(ALARM_SLOTS)


@pytest.mark.parametrize("level", [1, 2, 3])
def test_each_severity_round_trips(level: int) -> None:
    """Values 1/2/3 are the app's Level1/2/3 Fault; 0 is healthy."""
    for slot in ALARM_SLOTS:
        bits = bytearray(ALARM_FIELD_LEN)
        bits[slot.byte] = level << slot.shift
        decoded = decode_alarms(bytes(bits))
        assert decoded[slot.key] == level
        assert sum(1 for v in decoded.values() if v) == 1


def test_all_bits_set_lights_every_alarm() -> None:
    """The worst case must not raise and must not lose an alarm."""
    firing = active_alarms(b"\xff" * ALARM_FIELD_LEN)
    assert len(firing) == len(ALARM_SLOTS)
    assert all(level is AlarmLevel.LEVEL3 for _, level in firing)


def test_unmapped_bits_flags_slots_the_app_never_reads() -> None:
    """Byte 0 bits 4-5 and byte 5 bits 4-7 are not read by setData()."""
    assert unmapped_bits(HEALTHY_BITS) == 0
    assert unmapped_bits(FAULTY_BITS) == 0

    reserved = bytearray(ALARM_FIELD_LEN)
    reserved[0] = 0b0011_0000
    assert unmapped_bits(bytes(reserved)) == 0b0011_0000

    reserved = bytearray(ALARM_FIELD_LEN)
    reserved[5] = 0b1111_0000
    assert unmapped_bits(bytes(reserved)) == 0b1111_0000 << 40


def test_short_field_does_not_raise() -> None:
    """A truncated frame should degrade, not crash."""
    assert decode_alarms(b"\x00\x00\x30")["CellVoltageUnder"] is AlarmLevel.LEVEL3
    assert decode_alarms(b"")["CellVoltageUnder"] is AlarmLevel.NONE


class TestBatteryReading:
    """The reading-level view callers actually use."""

    def test_faulty(self) -> None:
        battery = BatteryReading(serial="X", position=1, alarm_bits=FAULTY_BITS)
        assert battery.has_fault is True
        assert battery.alarm_level is AlarmLevel.LEVEL3
        assert [slot.key for slot, _ in battery.active_alarms] == [
            "CellVoltageUnder"
        ]
        assert battery.unmapped_alarm_bits == 0

    def test_healthy(self) -> None:
        battery = BatteryReading(serial="X", position=1, alarm_bits=HEALTHY_BITS)
        assert battery.has_fault is False
        assert battery.alarm_level is AlarmLevel.NONE
        assert battery.active_alarms == ()

    def test_never_reported_is_not_the_same_as_healthy(self) -> None:
        battery = BatteryReading(serial="X", position=1)
        assert battery.has_fault is None
        assert battery.alarm_level is None
        assert battery.alarms == {}
