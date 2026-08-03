"""A held connection that keeps receiving, instead of a poll that reconnects.

The gateway streams unprompted once notifications are enabled, and it streams
for the whole bank at once: in a 182-second capture all four batteries emitted
cell frames every ~5.1 s concurrently, and kept doing so for 81 s after the app
sent its last byte. Connecting is the expensive part (~12 s of a ~18 s poll),
so a connection that is torn down between polls spends most of its life paying
setup costs for data that is already flowing.

Holding the connection instead gives fresh cell voltages every few seconds --
what the vendor app shows -- and drops the per-poll connection storm entirely.
The cost is that the gateway accepts only one central at a time, so while this
runs no other app can connect. :meth:`TensiteClusterStream.async_stop` releases
it deliberately; that is what the integration's circuit-breaker switch calls.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from bleak import BleakClient
from bleak.backends.device import BLEDevice

from .assembler import ReadingAssembler
from .client import Connector, TensiteClusterClient, TensiteError
from .const import (
    DEFAULT_CONNECT_TIMEOUT,
    KEEPALIVE_INTERVAL,
    NOTIFY_CHAR,
    RECONNECT_BACKOFF_INITIAL,
    RECONNECT_BACKOFF_MAX,
    REQUEST_CHAR,
    STREAM_UPDATE_THROTTLE,
)
from .models import ClusterReading
from .protocol import build_request

_LOGGER = logging.getLogger(__name__)

__all__ = ["TensiteClusterStream"]

#: Called with each new reading. Runs on the event loop; must not block.
UpdateCallback = Callable[[ClusterReading], None]

#: Called when the connection goes up or down, so callers can surface it.
StateCallback = Callable[[bool], None]


class TensiteClusterStream:
    """Keeps one BLE connection open and pushes readings as frames arrive.

    Started with :meth:`async_start`, which returns once the connection is up
    (or raises if it cannot be made). It then maintains itself: a dropped
    connection is retried with backoff until :meth:`async_stop`.
    """

    def __init__(
        self,
        device: BLEDevice | str,
        *,
        serial: str | None = None,
        on_update: UpdateCallback,
        on_connection_change: StateCallback | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        update_throttle: float = STREAM_UPDATE_THROTTLE,
        keepalive_interval: float = KEEPALIVE_INTERVAL,
        backoff_initial: float = RECONNECT_BACKOFF_INITIAL,
        backoff_max: float = RECONNECT_BACKOFF_MAX,
        connector: Connector | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Args:
            device: A resolved ``BLEDevice`` (preferred) or a bare address.
            serial: Master's serial, used to build the keepalive request.
            on_update: Receives a reading whenever new frames have arrived, at
                most once per *update_throttle* seconds.
            on_connection_change: Receives True on connect, False on drop.
            update_throttle: Floor on the gap between callbacks. Frames arrive
                in bursts of several per second across the bank; without this,
                every burst would push a state update per entity.
            keepalive_interval: How often to send the link-test frame. The
                stream does not depend on it -- see the constant's note.
            connector: Override how the connection is established. It is called
                with the device and a ``disconnected_callback`` keyword.
        """
        self._device = device
        self._serial = serial
        self._on_update = on_update
        self._on_connection_change = on_connection_change
        self._connect_timeout = connect_timeout
        self._update_throttle = update_throttle
        self._keepalive_interval = keepalive_interval
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._connector = connector
        self._logger = logger or _LOGGER

        self._assembler: ReadingAssembler | None = None
        self._client: BleakClient | None = None
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self._connected = asyncio.Event()
        #: Set by the disconnect callback to wake the run loop.
        self._dropped = asyncio.Event()
        self._pending_update = False
        self._flush_handle: asyncio.TimerHandle | None = None
        self._reconnects = 0
        self._last_error: str | None = None

    # -- state ---------------------------------------------------------------

    @property
    def address(self) -> str:
        return self._device if isinstance(self._device, str) else self._device.address

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def is_running(self) -> bool:
        """Whether the stream is maintaining a connection (or trying to)."""
        return self._task is not None and not self._task.done()

    @property
    def reconnects(self) -> int:
        """How many times the connection has been re-established since start."""
        return self._reconnects

    @property
    def last_error(self) -> str | None:
        """Why the most recent connection attempt failed, if one did."""
        return self._last_error

    @property
    def reading(self) -> ClusterReading | None:
        """Everything received so far on the current run, or None."""
        return self._assembler.reading() if self._assembler else None

    def update_device(self, device: BLEDevice) -> None:
        """Adopt a freshly resolved device.

        Home Assistant re-resolves a ``BLEDevice`` as advertisements arrive, and
        a stale one can point at an adapter that no longer sees the battery. The
        next reconnect picks this up; the current connection is left alone.
        """
        self._device = device

    # -- lifecycle -----------------------------------------------------------

    async def async_start(self, timeout: float | None = None) -> None:
        """Connect and begin streaming; return once the first connection is up.

        Raises whatever the connection attempt raised if it cannot be made, so
        that setup fails loudly rather than sitting in a silent retry loop.
        """
        if self.is_running:
            return
        self._stopping = False
        self._last_error = None
        self._task = asyncio.get_running_loop().create_task(
            self._run(), name=f"tensite-stream-{self.address}"
        )
        wait = timeout if timeout is not None else self._connect_timeout * 2
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=wait)
        except asyncio.TimeoutError:
            await self.async_stop()
            # The run loop swallowed the real failure in order to retry it;
            # report that rather than a bare timeout.
            raise TensiteError(
                f"{self.address}: could not start streaming within {wait:.0f}s"
                + (f" ({self._last_error})" if self._last_error else "")
            ) from None
        except asyncio.CancelledError:
            await self.async_stop()
            raise

    async def async_stop(self) -> None:
        """Disconnect and stop reconnecting, freeing the gateway for others."""
        self._stopping = True
        self._dropped.set()
        task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await self._async_teardown()
        self._cancel_flush()
        self._connected.clear()

    # -- internals -----------------------------------------------------------

    async def _run(self) -> None:
        """Hold the connection open, reconnecting with backoff when it drops."""
        backoff = self._backoff_initial
        while not self._stopping:
            try:
                await self._async_open()
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 -- any failure means retry
                self._last_error = f"{type(err).__name__}: {err}"
                self._logger.debug(
                    "%s: reconnecting in %.0fs after %s",
                    self.address,
                    backoff,
                    self._last_error,
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self._backoff_max)
                continue

            backoff = self._backoff_initial
            try:
                await self._async_hold()
            finally:
                await self._async_teardown()
            if not self._stopping:
                self._reconnects += 1
                self._logger.debug("%s: connection dropped, reopening", self.address)

    async def _async_open(self) -> None:
        """Connect, subscribe, and prime the stream."""
        # A fresh assembler per connection: frames from a session that has ended
        # describe a bank we are no longer listening to, and a battery removed
        # from the bank must not linger in the reading.
        self._assembler = ReadingAssembler(
            self.address, serial=self._serial, logger=self._logger
        )
        self._dropped.clear()

        client = TensiteClusterClient(
            self._device,
            serial=self._serial,
            connect_timeout=self._connect_timeout,
            connector=self._connector,
            logger=self._logger,
        )
        # bleak takes the disconnect callback at construction only, so it has to
        # be handed down through the connect call rather than attached after.
        self._client = await client.async_connect(self._on_disconnected)
        await self._client.start_notify(NOTIFY_CHAR, self._on_notify)

        # Not needed to start the stream -- the capture shows frames arriving
        # before the app writes anything -- but it is the one frame we know is
        # safe to send, and the app sends it too.
        await self._async_send_keepalive()

        self._connected.set()
        self._logger.debug("%s: streaming", self.address)
        if self._on_connection_change:
            self._on_connection_change(True)

    async def _async_hold(self) -> None:
        """Sit on the connection, sending a keepalive, until it drops."""
        while not self._stopping and not self._dropped.is_set():
            try:
                await asyncio.wait_for(
                    self._dropped.wait(), timeout=self._keepalive_interval
                )
                return
            except asyncio.TimeoutError:
                pass
            if not await self._async_send_keepalive():
                return

    async def _async_send_keepalive(self) -> bool:
        """Send the link-test frame. False if the connection is gone."""
        if not self._serial or self._client is None:
            return True
        try:
            await self._client.write_gatt_char(
                REQUEST_CHAR, build_request(self._serial), response=True
            )
        except Exception as err:  # noqa: BLE001 -- a failed write means dropped
            self._last_error = f"{type(err).__name__}: {err}"
            self._logger.debug("%s: keepalive failed: %s", self.address, err)
            return False
        return True

    def _on_disconnected(self, _client: BleakClient) -> None:
        self._dropped.set()
        self._connected.clear()
        if self._on_connection_change:
            self._on_connection_change(False)

    async def _async_teardown(self) -> None:
        client, self._client = self._client, None
        self._assembler = None
        self._connected.clear()
        if client is None:
            return
        try:
            await client.disconnect()
        except Exception:  # noqa: BLE001 -- teardown must never raise
            self._logger.debug("%s: disconnect failed, ignoring", self.address)

    # -- notification path ---------------------------------------------------

    def _on_notify(self, _sender: Any, data: bytearray) -> None:
        assembler = self._assembler
        if assembler is None or self._stopping:
            return
        if not assembler.feed(bytes(data)):
            return
        self._schedule_flush()

    def _schedule_flush(self) -> None:
        """Coalesce a burst of frames into one callback.

        Frames arrive several per second across the bank. Pushing an update per
        frame would write every entity's state several times a second for data
        that changed in one battery, so updates are rate-limited and the most
        recent state wins.
        """
        if self._flush_handle is not None:
            self._pending_update = True
            return
        self._flush()
        loop = asyncio.get_running_loop()
        self._flush_handle = loop.call_later(self._update_throttle, self._on_throttle_end)

    def _on_throttle_end(self) -> None:
        self._flush_handle = None
        if self._pending_update:
            self._pending_update = False
            self._schedule_flush()

    def _flush(self) -> None:
        reading = self.reading
        if reading is None:
            return
        try:
            self._on_update(reading)
        except Exception:  # noqa: BLE001 -- a bad consumer must not kill the stream
            self._logger.exception("%s: update callback failed", self.address)

    def _cancel_flush(self) -> None:
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None
        self._pending_update = False
