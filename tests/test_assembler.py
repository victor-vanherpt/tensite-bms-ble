"""The shared frame-to-reading accumulator.

Exercised indirectly by every client test; these cover the properties the
streaming path leans on and a one-shot read never notices -- that state
accumulates across feeds, and that a battery which goes quiet keeps the values
it last reported.
"""

from __future__ import annotations

from tensite_bms_ble import ReadingAssembler

from .test_client import SUMMARY_PAYLOAD, TEMPS_PAYLOAD
from .test_protocol import CELLS_GROUND_TRUTH, CELLS_PAYLOAD, _make_frame

ADDRESS = "AA:BB:CC:DD:EE:FF"
MASTER = "1417725SLKOPGG08146"
SLAVE = "1417607SLKOPGG08051"


def _assembler() -> ReadingAssembler:
    return ReadingAssembler(ADDRESS, serial=MASTER)


class TestAccumulation:
    def test_nothing_received_is_no_reading(self):
        assert _assembler().reading() is None

    def test_frame_types_from_separate_feeds_land_on_one_battery(self):
        """On a held connection the pieces arrive seconds apart."""
        assembler = _assembler()
        assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0))
        assert not assembler.reading().batteries[MASTER].has_cells

        assembler.feed(_make_frame(0x05, CELLS_PAYLOAD, serial=MASTER, position=0x01A0))
        assembler.feed(_make_frame(0x21, TEMPS_PAYLOAD, serial=MASTER, position=0x01A0))

        battery = assembler.reading().batteries[MASTER]
        assert battery.voltage == 51.8
        assert list(battery.cell_voltages_mv) == CELLS_GROUND_TRUTH
        assert list(battery.temperatures) == [38, 40, -50, -30]

    def test_a_battery_that_goes_quiet_keeps_its_last_values(self):
        assembler = _assembler()
        for serial, position in ((MASTER, 0x01A0), (SLAVE, 0x0103)):
            assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=serial, position=position))
            assembler.feed(_make_frame(0x05, CELLS_PAYLOAD, serial=serial, position=position))

        # Only the master speaks from here on.
        assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0))
        assert set(assembler.reading().batteries) == {MASTER, SLAVE}

    def test_feed_reports_which_batteries_changed(self):
        assembler = _assembler()
        touched = assembler.feed(
            _make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0)
        )
        assert touched == {MASTER}
        assert assembler.feed(b"") == set()

    def test_a_frame_split_across_feeds_is_reassembled(self):
        """Notifications are MTU-sized fragments, not whole frames."""
        assembler = _assembler()
        frame = _make_frame(0x05, CELLS_PAYLOAD, serial=MASTER, position=0x01A0)
        for start in range(0, len(frame), 20):
            assembler.feed(frame[start : start + 20])
        assert list(assembler.reading().batteries[MASTER].cell_voltages_mv) == (
            CELLS_GROUND_TRUTH
        )


class TestCompleteness:
    def test_a_summary_alone_is_not_complete(self):
        """Summaries arrive far more often than cells; counting them would end
        a poll with cell-less data."""
        assembler = _assembler()
        assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0))
        assert assembler.complete_count() == 0

    def test_summary_and_cells_together_are_complete(self):
        assembler = _assembler()
        assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0))
        assembler.feed(_make_frame(0x05, CELLS_PAYLOAD, serial=MASTER, position=0x01A0))
        assert assembler.complete_count() == 1


class TestRoster:
    def test_unknown_until_a_topology_frame_arrives(self):
        assembler = _assembler()
        assembler.feed(_make_frame(0x00, SUMMARY_PAYLOAD, serial=MASTER, position=0x01A0))
        assert assembler.roster_count == 0
        assert assembler.reading().roster_count is None
