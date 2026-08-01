"""Client tests against a faked GATT peer -- no hardware required."""

from __future__ import annotations

import asyncio

import pytest

from tensite_bms_ble import TensiteClusterClient, TensiteNoDataError
from tensite_bms_ble.const import NOTIFY_CHAR, REQUEST_CHAR
from tensite_bms_ble.models import BatteryReading

from .test_protocol import APP_REQUEST, CELLS_GROUND_TRUTH, CELLS_PAYLOAD, _make_frame

MASTER_SERIAL = "1417725SLKOPGG08146"

BANK = {
    "1417607SLKOPGG08051": 0x0103,
    "1417607SLKOPGG08313": 0x0102,
    "1417725SLKOPGG08099": 0x0101,
    MASTER_SERIAL: 0x01A0,
}


class FakeBleakClient:
    """Minimal stand-in that replays the bank the way the gateway does."""

    def __init__(self, *, chunk_size: int | None = None, emit: bool = True) -> None:
        self.writes: list[tuple[str, bytes]] = []
        self.notify_started = False
        self.notify_stopped = False
        self.disconnected = False
        self._chunk_size = chunk_size
        self._emit = emit
        self._callback = None

    async def start_notify(self, char, callback):
        assert char == NOTIFY_CHAR
        self.notify_started = True
        self._callback = callback
        if self._emit:
            asyncio.get_running_loop().call_soon(self._replay)

    def _replay(self):
        stream = b"".join(
            _make_frame(0x01, bytes.fromhex("e6f8bbcbbc10ab6d"), serial=serial)
            + _make_frame(0x05, CELLS_PAYLOAD, serial=serial, position=position)
            for serial, position in BANK.items()
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
        with pytest.raises(TensiteNoDataError, match="no cell frames"):
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
