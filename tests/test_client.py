"""Client tests against a faked GATT peer -- no hardware required."""

from __future__ import annotations

import asyncio

import pytest

from tensite_bms_ble import (
    ClusterReading,
    TensiteClusterClient,
    TensiteNoDataError,
    merge_readings,
)
from tensite_bms_ble.const import NOTIFY_CHAR, REQUEST_CHAR
from tensite_bms_ble.models import BatteryReading

from .test_protocol import (
    APP_REQUEST,
    CELLS_GROUND_TRUTH,
    CELLS_PAYLOAD,
    TestDecodeSummary,
    _make_frame,
    _mask,
)

MASTER_SERIAL = "1417725SLKOPGG08146"

SUMMARY_PAYLOAD = _mask(TestDecodeSummary.PLAIN)
TEMPS_PAYLOAD = _mask(bytes([88, 90, 0, 20]))

BANK = {
    "1417607SLKOPGG08051": 0x0103,
    "1417607SLKOPGG08313": 0x0102,
    "1417725SLKOPGG08099": 0x0101,
    MASTER_SERIAL: 0x01A0,
}


class FakeBleakClient:
    """Minimal stand-in that replays the bank the way the gateway does."""

    def __init__(
        self,
        *,
        chunk_size: int | None = None,
        emit: bool = True,
        summary_only: bool = False,
    ) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self.notify_started = False
        self.notify_stopped = False
        self.disconnected = False
        self._chunk_size = chunk_size
        self._emit = emit
        self._summary_only = summary_only
        self._callback = None

    async def start_notify(self, char, callback):
        assert char == NOTIFY_CHAR
        self.notify_started = True
        self._callback = callback
        if self._emit:
            asyncio.get_running_loop().call_soon(self._replay)

    def _replay(self):
        # Mirrors the real gateway: keystream, summary, cells and temperatures
        # per battery. A poll is only complete once summary *and* cells arrive.
        def frames_for(serial, position):
            out = _make_frame(
                0x01, bytes.fromhex("e6f8bbcbbc10ab6d"), serial=serial
            ) + _make_frame(0x00, SUMMARY_PAYLOAD, serial=serial, position=position)
            if self._summary_only:
                return out
            return (
                out
                + _make_frame(0x05, CELLS_PAYLOAD, serial=serial, position=position)
                + _make_frame(0x21, TEMPS_PAYLOAD, serial=serial, position=position)
            )

        stream = b"".join(
            frames_for(serial, position) for serial, position in BANK.items()
        )
        size = self._chunk_size or len(stream)
        for start in range(0, len(stream), size):
            self._callback(None, bytearray(stream[start : start + size]))

    async def write_gatt_char(self, char, data, response=False):
        self.writes.append((char, bytes(data)))

    async def stop_notify(self, char):
        self.notify_stopped = True

    async def disconnect(self):
        self.disconnected = True


def _client(fake: FakeBleakClient, **kwargs) -> TensiteClusterClient:
    async def connector(_device):
        return fake

    # Short listen window by default: the library's real default is 90s, and a
    # bug that stops `expect` from being satisfied would otherwise stall the
    # suite for minutes per test instead of failing quickly.
    kwargs.setdefault("listen_timeout", 5.0)
    return TensiteClusterClient(
        _FakeDevice(), serial=MASTER_SERIAL, connector=connector, **kwargs
    )


class _FakeDevice:
    address = "AA:BB:CC:DD:EE:FF"
    name = "ESP32"


class TestAsyncRead:
    async def test_reads_whole_bank_from_one_connection(self):
        fake = FakeBleakClient()
        reading = await _client(fake).async_read(expect=4)

        assert reading.battery_count == 4
        assert set(reading.batteries) == set(BANK)
        assert reading.master_serial == MASTER_SERIAL
        assert reading.cluster_id == 1
        for battery in reading.batteries.values():
            assert list(battery.cell_voltages_mv) == CELLS_GROUND_TRUTH

    async def test_sends_the_vendor_request_frame(self):
        fake = FakeBleakClient()
        await _client(fake).async_read(expect=4)
        assert fake.writes == [(REQUEST_CHAR, APP_REQUEST)]

    async def test_skips_request_when_serial_unknown(self):
        fake = FakeBleakClient()

        async def connector(_device):
            return fake

        client = TensiteClusterClient(_FakeDevice(), connector=connector)
        await client.async_read(expect=4)
        assert fake.writes == [], "no serial means nothing to address a request to"

    async def test_reassembles_frames_split_across_notifications(self):
        """Real notifications are MTU-sized fragments, not whole frames."""
        fake = FakeBleakClient(chunk_size=20)
        reading = await _client(fake).async_read(expect=4)
        assert reading.battery_count == 4

    async def test_always_disconnects(self):
        fake = FakeBleakClient()
        await _client(fake).async_read(expect=4)
        assert fake.notify_started
        assert fake.notify_stopped
        assert fake.disconnected

    async def test_disconnects_even_when_nothing_arrives(self):
        fake = FakeBleakClient(emit=False)
        with pytest.raises(TensiteNoDataError, match="no battery frames"):
            await _client(fake, listen_timeout=0.05).async_read()
        assert fake.disconnected, "a failed read must not leak the connection slot"

    async def test_expect_returns_before_the_timeout(self):
        fake = FakeBleakClient()
        client = _client(fake, listen_timeout=30.0)
        reading = await asyncio.wait_for(client.async_read(expect=4), timeout=5.0)
        assert reading.battery_count == 4

    async def test_connect_timeout_is_clamped_to_ten_seconds(self):
        """BlueZ needs >=10s to resolve services on a first connection."""
        client = TensiteClusterClient(_FakeDevice(), connect_timeout=1.0)
        assert client._connect_timeout == 10.0


class TestReadingAssembly:
    """A battery's state is built from several frame types arriving separately."""

    async def test_merges_every_frame_type(self):
        reading = await _client(FakeBleakClient()).async_read(expect=4)
        battery = reading.batteries[MASTER_SERIAL]
        assert battery.voltage == 51.8
        assert battery.soc == 49.7
        assert battery.current == 20.3
        assert list(battery.cell_voltages_mv) == CELLS_GROUND_TRUTH
        assert list(battery.temperatures) == [38, 40, -50, -30]
        assert battery.faulty_temperature_sensors == 2

    async def test_expect_requires_summary_and_cells(self):
        """Summaries alone must not satisfy `expect` -- they arrive far more
        often than cell frames, so counting them would end the poll with
        cell-less data. The poll should run its full window instead."""
        fake = FakeBleakClient(summary_only=True)
        loop = asyncio.get_running_loop()
        started = loop.time()
        reading = await _client(fake, listen_timeout=0.4).async_read(expect=4)
        assert loop.time() - started >= 0.35, "returned early on summaries alone"
        assert reading.battery_count == 4
        assert all(not b.has_cells for b in reading.batteries.values())

    async def test_partial_battery_still_returned(self):
        """A unit that sent a summary but no cells is better than nothing."""
        fake = FakeBleakClient(summary_only=True)
        reading = await _client(fake, listen_timeout=0.3).async_read()
        assert reading.battery_count == 4
        battery = reading.batteries[MASTER_SERIAL]
        assert battery.voltage == 51.8
        assert not battery.has_cells

    async def test_cluster_aggregates(self):
        reading = await _client(FakeBleakClient()).async_read(expect=4)
        assert reading.soc == 49.7
        assert reading.current == pytest.approx(20.3 * 4)  # parallel: currents add
        assert reading.total_voltage == pytest.approx(51.8)  # parallel: voltages agree
        # Cluster extremes come from each battery's summary, where this
        # fixture reports 42 C / 38 C -- not from the per-sensor list.
        assert reading.max_temperature == 42
        assert reading.min_temperature == 38


class TestCellExtremeDisagreement:
    """The BMS's own cell extremes do not always match its cell list."""

    def _reading(self, cells, summary_min, summary_max):
        from tensite_bms_ble.protocol import Summary

        return BatteryReading(
            serial=MASTER_SERIAL,
            position=0x01A0,
            cell_voltages_mv=tuple(cells),
            summary=Summary(
                voltage=53.1,
                current=-3.2,
                soc=62.0,
                max_cell_mv=summary_max,
                min_cell_mv=summary_min,
                max_cell_index=10,
                min_cell_index=2,
                max_temperature=42,
                min_temperature=38,
                daily_charge_kwh=1.4,
                daily_discharge_kwh=0.9,
            ),
        )

    def test_extremes_come_from_the_cell_list(self):
        """So they always agree with the 16 per-cell values."""
        battery = self._reading(CELLS_GROUND_TRUTH, 3300, 3330)
        assert battery.min_cell_mv == min(CELLS_GROUND_TRUTH)
        assert battery.max_cell_mv == max(CELLS_GROUND_TRUTH)

    def test_reported_extremes_preserved_separately(self):
        battery = self._reading(CELLS_GROUND_TRUTH, 3300, 3330)
        assert battery.reported_min_cell_mv == 3300
        assert battery.reported_max_cell_mv == 3330
        assert battery.cell_extremes_disagree

    def test_no_disagreement_when_they_match(self):
        battery = self._reading(
            CELLS_GROUND_TRUTH, min(CELLS_GROUND_TRUTH), max(CELLS_GROUND_TRUTH)
        )
        assert not battery.cell_extremes_disagree


class TestBatteryReading:
    def _reading(self, cells):
        return BatteryReading(
            serial=MASTER_SERIAL, position=0x01A0, cell_voltages_mv=tuple(cells)
        )

    def test_derived_metrics(self):
        battery = self._reading(CELLS_GROUND_TRUTH)
        assert battery.cell_count == 16
        assert battery.min_cell_mv == 3204
        assert battery.max_cell_mv == 3259
        assert battery.delta_mv == 55
        assert battery.total_voltage == pytest.approx(51.969)

    def test_position_helpers(self):
        assert self._reading(CELLS_GROUND_TRUTH).is_master
        assert self._reading(CELLS_GROUND_TRUTH).position_label == "C01/PA0"
        assert self._reading(CELLS_GROUND_TRUTH).cluster_id == 1

    def test_flags_implausible_cells(self):
        cells = list(CELLS_GROUND_TRUTH)
        cells[3] = 12
        assert self._reading(cells).implausible_cells == (4,)

    def test_no_flags_for_healthy_pack(self):
        assert self._reading(CELLS_GROUND_TRUTH).implausible_cells == ()


class TestMergeReadings:
    """A poll can miss part of the bank; merging stops entities flapping."""

    def _cluster(self, **batteries):
        return ClusterReading(
            address="AA:BB:CC:DD:EE:FF",
            master_serial=MASTER_SERIAL,
            batteries=batteries,
        )

    def test_carries_cells_forward_when_a_poll_misses_them(self):
        from tensite_bms_ble.protocol import Summary

        full = self._cluster(
            **{
                MASTER_SERIAL: BatteryReading(
                    serial=MASTER_SERIAL,
                    position=0x01A0,
                    cell_voltages_mv=tuple(CELLS_GROUND_TRUTH),
                    temperatures=(38, 40),
                )
            }
        )
        summary_only = self._cluster(
            **{
                MASTER_SERIAL: BatteryReading(
                    serial=MASTER_SERIAL,
                    position=0x01A0,
                    summary=Summary(52.0, 1.0, 50.0, 3300, 3200, 10, 2, 40, 38, 0.2, 0.2),
                )
            }
        )
        merged = merge_readings(full, summary_only)
        battery = merged.batteries[MASTER_SERIAL]
        assert list(battery.cell_voltages_mv) == CELLS_GROUND_TRUTH
        assert list(battery.temperatures) == [38, 40]
        assert battery.voltage == 52.0, "newest summary must win"

    def test_retains_a_battery_absent_from_the_latest_poll(self):
        previous = self._cluster(
            **{
                MASTER_SERIAL: BatteryReading(serial=MASTER_SERIAL, position=0x01A0),
                "1417725SLKOPGG08099": BatteryReading(
                    serial="1417725SLKOPGG08099", position=0x0101
                ),
            }
        )
        latest = self._cluster(
            **{MASTER_SERIAL: BatteryReading(serial=MASTER_SERIAL, position=0x01A0)}
        )
        assert merge_readings(previous, latest).battery_count == 2

    def test_no_previous_returns_latest(self):
        latest = self._cluster(
            **{MASTER_SERIAL: BatteryReading(serial=MASTER_SERIAL, position=0x01A0)}
        )
        assert merge_readings(None, latest) is latest
