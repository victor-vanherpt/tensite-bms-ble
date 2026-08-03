"""The held connection, against a faked GATT peer.

The behaviour under test comes from the 2026-07-31 capture: the gateway streams
unprompted once notifications are enabled, every battery concurrently, roughly
every 5 s, and keeps going with nothing sent to it. So the stream must push
readings as frames arrive rather than asking for them, and must never depend on
its own writes to keep data flowing.
"""

from __future__ import annotations

import asyncio

import pytest

from tensite_bms_ble import ClusterReading, TensiteClusterStream, TensiteError
from tensite_bms_ble.const import REQUEST_CHAR

from .test_client import BANK, MASTER_SERIAL, FakeBleakClient, _FakeDevice
from .test_protocol import APP_REQUEST, CELLS_GROUND_TRUTH


class StreamingFake(FakeBleakClient):
    """A peer that keeps emitting, and can be made to drop the link."""

    def __init__(self, **kwargs) -> None:
        super().__init__(emit=False, **kwargs)
        self.is_connected = True
        self.disconnected_callback = None

    def emit(self) -> None:
        """Deliver one round of frames for the whole bank."""
        self._replay()

    def drop(self) -> None:
        """Simulate the peer going away mid-stream."""
        self.is_connected = False
        self.disconnected = True
        if self.disconnected_callback is not None:
            self.disconnected_callback(self)


class Harness:
    """Builds streams over a sequence of fake peers, one per connection."""

    def __init__(self, *peers: StreamingFake, fail_first: int = 0) -> None:
        self.peers = list(peers)
        self.connections = 0
        self.updates: list[ClusterReading] = []
        self.connection_events: list[bool] = []
        self._fail_first = fail_first

    async def connector(self, _device, disconnected_callback=None):
        self.connections += 1
        if self.connections <= self._fail_first:
            raise OSError("no connection slot")
        peer = self.peers[min(self.connections - 1 - self._fail_first, len(self.peers) - 1)]
        peer.disconnected_callback = disconnected_callback
        return peer

    def stream(self, **kwargs) -> TensiteClusterStream:
        kwargs.setdefault("update_throttle", 0.02)
        kwargs.setdefault("keepalive_interval", 30.0)
        kwargs.setdefault("backoff_initial", 0.02)
        kwargs.setdefault("backoff_max", 0.05)
        return TensiteClusterStream(
            _FakeDevice(),
            serial=MASTER_SERIAL,
            on_update=self.updates.append,
            on_connection_change=self.connection_events.append,
            connector=self.connector,
            **kwargs,
        )


async def settle(times: int = 3) -> None:
    """Let queued callbacks and timer handles run."""
    for _ in range(times):
        await asyncio.sleep(0.05)


class TestStreaming:
    async def test_pushes_a_reading_as_frames_arrive(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        try:
            peer.emit()
            await settle()
            assert harness.updates, "frames arrived but nothing was pushed"
            reading = harness.updates[-1]
            assert set(reading.batteries) == set(BANK)
            assert list(
                reading.batteries[MASTER_SERIAL].cell_voltages_mv
            ) == CELLS_GROUND_TRUTH
        finally:
            await stream.async_stop()

    async def test_keeps_streaming_without_being_asked(self):
        """The capture shows 81 s of cell frames after the app's last write."""
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream(keepalive_interval=3600.0)
        await stream.async_start()
        try:
            writes_after_start = len(peer.writes)
            for _ in range(3):
                peer.emit()
                await settle()
            assert len(harness.updates) >= 3
            assert len(peer.writes) == writes_after_start, "should not need to poll"
        finally:
            await stream.async_stop()

    async def test_bursts_are_coalesced_into_one_update(self):
        """Four batteries at once must not mean four rewrites of every entity."""
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream(update_throttle=5.0)
        await stream.async_start()
        try:
            for _ in range(4):
                peer.emit()
            await settle()
            assert len(harness.updates) == 1
        finally:
            await stream.async_stop()

    async def test_a_later_change_is_still_delivered_after_the_throttle(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream(update_throttle=0.05)
        await stream.async_start()
        try:
            peer.emit()
            await settle(1)
            peer.emit()
            await settle(4)
            assert len(harness.updates) >= 2, "throttle must delay, not drop"
        finally:
            await stream.async_stop()

    async def test_sends_the_vendor_request_on_connect(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        try:
            assert peer.writes == [(REQUEST_CHAR, APP_REQUEST)]
        finally:
            await stream.async_stop()

    async def test_keepalive_repeats_on_its_interval(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream(keepalive_interval=0.05)
        await stream.async_start()
        try:
            await settle(4)
            assert len(peer.writes) > 1
            assert {char for char, _ in peer.writes} == {REQUEST_CHAR}
        finally:
            await stream.async_stop()

    async def test_reading_is_available_without_a_callback_fired(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        try:
            assert stream.reading is None, "nothing received yet"
            peer.emit()
            await settle()
            assert stream.reading is not None
            assert stream.reading.battery_count == 4
        finally:
            await stream.async_stop()


class TestConnectionLifecycle:
    async def test_reconnects_after_a_drop(self):
        first, second = StreamingFake(), StreamingFake()
        harness = Harness(first, second)
        stream = harness.stream()
        await stream.async_start()
        try:
            first.drop()
            await settle(4)
            assert harness.connections == 2
            assert stream.reconnects == 1
            assert stream.is_connected
            second.emit()
            await settle()
            assert harness.updates[-1].battery_count == 4
        finally:
            await stream.async_stop()

    async def test_connection_changes_are_reported(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        assert harness.connection_events == [True]
        peer.drop()
        await settle(2)
        await stream.async_stop()
        assert harness.connection_events[:2] == [True, False]

    async def test_a_reconnect_starts_from_a_clean_slate(self):
        """Frames from a session that ended describe a bank we left."""
        first, second = StreamingFake(), StreamingFake()
        harness = Harness(first, second)
        stream = harness.stream()
        await stream.async_start()
        try:
            first.emit()
            await settle()
            assert stream.reading.battery_count == 4
            first.drop()
            await settle(4)
            assert stream.reading is None, "old bank must not survive the drop"
        finally:
            await stream.async_stop()

    async def test_start_retries_a_failed_first_attempt(self):
        peer = StreamingFake()
        harness = Harness(peer, fail_first=1)
        stream = harness.stream()
        await stream.async_start(timeout=2.0)
        try:
            assert stream.is_connected
            assert harness.connections == 2
        finally:
            await stream.async_stop()

    async def test_start_raises_when_it_cannot_connect_at_all(self):
        harness = Harness(StreamingFake(), fail_first=99)
        stream = harness.stream()
        with pytest.raises(TensiteError, match="could not start streaming"):
            await stream.async_start(timeout=0.2)
        assert not stream.is_running, "a failed start must not leave a retry loop"

    async def test_start_reports_why_it_failed(self):
        harness = Harness(StreamingFake(), fail_first=99)
        stream = harness.stream()
        with pytest.raises(TensiteError, match="no connection slot"):
            await stream.async_start(timeout=0.2)


class TestCircuitBreaker:
    """Stopping must actually free the gateway for another app."""

    async def test_stop_disconnects(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        await stream.async_stop()
        assert peer.disconnected
        assert not stream.is_connected
        assert not stream.is_running

    async def test_stop_does_not_reconnect(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        await stream.async_stop()
        connections = harness.connections
        await settle(4)
        assert harness.connections == connections, "still holding the slot"

    async def test_stop_is_idempotent(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        await stream.async_stop()
        await stream.async_stop()

    async def test_stop_before_start_is_harmless(self):
        await Harness(StreamingFake()).stream().async_stop()

    async def test_restart_after_stop(self):
        first, second = StreamingFake(), StreamingFake()
        harness = Harness(first, second)
        stream = harness.stream()
        await stream.async_start()
        await stream.async_stop()
        await stream.async_start()
        try:
            assert stream.is_connected
            second.emit()
            await settle()
            assert harness.updates[-1].battery_count == 4
        finally:
            await stream.async_stop()

    async def test_no_updates_after_stop(self):
        peer = StreamingFake()
        harness = Harness(peer)
        stream = harness.stream()
        await stream.async_start()
        await stream.async_stop()
        harness.updates.clear()
        peer.emit()
        await settle(2)
        assert harness.updates == []
