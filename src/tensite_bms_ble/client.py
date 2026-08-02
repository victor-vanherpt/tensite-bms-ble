"""BLE transport for Tensite battery clusters.

Home Assistant compatibility rules this module follows, per
https://developers.home-assistant.io/docs/bluetooth/:

* **Never construct a scanner when the caller supplies one.** Home Assistant
  hands out a shared, adapter-aware scanner via ``bluetooth.async_get_scanner``;
  running a second one is expensive and breaks when the user changes adapter
  settings. Every entry point here takes an optional ``scanner``.
* **Prefer an already-resolved ``BLEDevice``** over an address. Home Assistant
  can supply one from its own cache without scanning at all.
* **A ``BleakClient`` is never reused between connections** -- a fresh one is
  built for each read.
* **Connection timeouts are never below ten seconds**, because BlueZ has to
  resolve services on a first connection to a device.
* **Connections go through ``bleak_retry_connector.establish_connection``**,
  which handles the transient first-attempt failures that are normal on BLE.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from datetime import datetime, timezone
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak_retry_connector import (
    close_stale_connections_by_address,
    establish_connection,
)

from .const import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_LISTEN_TIMEOUT,
    MANUFACTURER_DATA_START,
    MANUFACTURER_ID,
    MIN_CONNECT_TIMEOUT,
    NOTIFY_CHAR,
    PROTO_DEVICE,
    REQUEST_CHAR,
    SERIAL_MARKER,
    TYPE_ALARM,
    TYPE_CELLS,
    TYPE_MODEL,
    TYPE_RELAY,
    TYPE_SUMMARY,
    TYPE_SWITCH,
    TYPE_TEMPERATURES,
)
from .models import BatteryReading, ClusterReading
from .protocol import (
    ParseStats,
    build_request,
    decode_alarm_bits,
    decode_cells,
    decode_model,
    decode_routes,
    decode_summary,
    decode_temperatures,
    parse_frames,
)

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "DiscoveredCluster",
    "TensiteClusterClient",
    "TensiteError",
    "TensiteNoDataError",
    "async_discover_clusters",
    "is_tensite_advertisement",
]

#: A callable that returns a *connected* BleakClient. Supplied by the caller to
#: override how connections are made; the default uses establish_connection.
Connector = Callable[[BLEDevice], Awaitable[BleakClient]]


def _complete(part: dict[str, Any]) -> bool:
    """Whether a battery has reported everything a poll waits for."""
    return bool(part.get("summary")) and bool(part.get("cell_voltages_mv"))


class TensiteError(Exception):
    """Base class for errors raised by this library."""


class TensiteNoDataError(TensiteError):
    """Connected successfully but no cell frames arrived before the timeout."""


@dataclass(frozen=True, slots=True)
class DiscoveredCluster:
    """A battery seen in an advertisement."""

    address: str
    serial: str | None
    rssi: int | None
    device: BLEDevice | None = None

    @property
    def name(self) -> str:
        return self.serial or self.address


def is_tensite_advertisement(adv: AdvertisementData) -> bool:
    """Whether an advertisement belongs to a Tensite/UhomeEnergy battery.

    Matches on manufacturer data first (0xE502 carrying ``UHOME``), because the
    local name is not always present in every advertisement.
    """
    payload = (adv.manufacturer_data or {}).get(MANUFACTURER_ID)
    if payload is not None and payload.startswith(MANUFACTURER_DATA_START):
        return True
    return SERIAL_MARKER in (adv.local_name or "")


def _serial_from_advertisement(adv: AdvertisementData) -> str | None:
    """Extract the serial from an advertisement's local name, if present.

    The serial is only ever in the *advertisement* local name. On macOS,
    ``BLEDevice.name`` returns CoreBluetooth's cached GATT Device Name, which
    for every unit in the bank is the useless string ``ESP32``.
    """
    name = adv.local_name or ""
    return name if SERIAL_MARKER in name else None


async def async_discover_clusters(
    scanner: BleakScanner | None = None,
    timeout: float = 8.0,
) -> list[DiscoveredCluster]:
    """Find Tensite batteries in range, strongest signal first.

    Pass Home Assistant's shared scanner (``bluetooth.async_get_scanner(hass)``)
    as *scanner*; a new one is only created when nothing is supplied, which is
    the standalone/CLI case.

    Note that advertising is intermittent -- a given battery can be absent from
    any single scan. Callers that need a specific unit should retry.
    """
    if scanner is not None:
        seen = getattr(scanner, "discovered_devices_and_advertisement_data", None)
        if seen:
            return _collect(seen)
        # A supplied scanner with nothing cached yet: ask it directly rather
        # than building our own.
        found = await scanner.discover(timeout=timeout, return_adv=True)
        return _collect(found)

    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    return _collect(found)


def _collect(
    seen: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> list[DiscoveredCluster]:
    clusters = [
        DiscoveredCluster(
            address=address,
            serial=_serial_from_advertisement(adv),
            rssi=adv.rssi,
            device=device,
        )
        for address, (device, adv) in seen.items()
        if is_tensite_advertisement(adv)
    ]
    clusters.sort(key=lambda c: c.rssi if c.rssi is not None else -999, reverse=True)
    return clusters


class TensiteClusterClient:
    """Reads every battery in one cluster over a single BLE connection.

    Connecting to the cluster master relays frames for the whole bank, each
    tagged with its own serial, so one connection covers every battery. The
    gateway accepts only one central at a time, which is precisely why this is
    modelled per *cluster* and not per battery.
    """

    def __init__(
        self,
        device: BLEDevice | str,
        *,
        serial: str | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        listen_timeout: float = DEFAULT_LISTEN_TIMEOUT,
        connector: Connector | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        """
        Args:
            device: A resolved ``BLEDevice`` (preferred -- Home Assistant can
                supply one without scanning) or a bare address string.
            serial: Master's serial. When known, the vendor app's request frame
                is sent; without it the client just listens, since the device
                broadcasts unprompted anyway.
            connect_timeout: Clamped to at least ten seconds.
            listen_timeout: Upper bound on how long to wait for frames.
            connector: Override how the connection is established. Defaults to
                ``bleak_retry_connector.establish_connection``.
        """
        self._device = device
        self._serial = serial
        self._connect_timeout = max(connect_timeout, MIN_CONNECT_TIMEOUT)
        self._listen_timeout = listen_timeout
        self._connector = connector
        self._logger = logger or _LOGGER

    @property
    def address(self) -> str:
        return self._device if isinstance(self._device, str) else self._device.address

    async def _async_connect(self) -> BleakClient:
        """Establish a connection with retries, using a fresh client."""
        if self._connector is not None:
            if isinstance(self._device, str):
                raise TensiteError(
                    "a custom connector requires a resolved BLEDevice, not an address"
                )
            return await self._connector(self._device)

        if isinstance(self._device, str):
            # Standalone use with a bare address. CoreBluetooth on macOS will
            # only connect to a peripheral it has already discovered in this
            # process, so callers there should resolve a BLEDevice first.
            client = BleakClient(self._device, timeout=self._connect_timeout)
            await client.connect()
            return client

        # Reap any connection left over from a previous read before opening a
        # new one. Nothing else will: a caller polling on a timer gets no
        # advertisement-driven housekeeping, and a connection that was not torn
        # down cleanly stays counted against the adapter. On a small adapter
        # that means three or four polls succeed and every one after fails with
        # "the proxy/adapter is out of connection slots" until the process
        # restarts, while the adapter itself is idle.
        await close_stale_connections_by_address(self.address)

        return await establish_connection(
            BleakClient,
            self._device,
            self._serial or self.address,
            timeout=self._connect_timeout,
        )

    async def async_read(
        self,
        expect: int | None = None,
        listen_timeout: float | None = None,
    ) -> ClusterReading:
        """Connect, gather one reading per battery, disconnect.

        Args:
            expect: Return as soon as this many batteries have reported rather
                than waiting out the timeout. The gateway round-robins the
                bank, so knowing the expected count shortens a poll a lot.
            listen_timeout: Override the instance default.

        Raises:
            TensiteNoDataError: connected, but no cell frames arrived in time.
        """
        timeout = listen_timeout if listen_timeout is not None else self._listen_timeout
        buffer = bytearray()
        stats = ParseStats()
        # Each battery's state is assembled from several frame types that
        # arrive independently, so accumulate per serial rather than replacing.
        parts: dict[str, dict[str, Any]] = {}
        enough = asyncio.Event()

        def _on_notify(_sender: Any, data: bytearray) -> None:
            buffer.extend(data)
            for frame in parse_frames(buffer, stats):
                if frame.proto != PROTO_DEVICE or SERIAL_MARKER not in frame.serial:
                    continue
                part = parts.setdefault(
                    frame.serial, {"position": frame.position}
                )
                part["position"] = frame.position
                try:
                    if frame.msg_type == TYPE_CELLS:
                        part["cell_voltages_mv"] = tuple(decode_cells(frame.payload))
                        part["cells_updated_at"] = datetime.now(tz=timezone.utc)
                    elif frame.msg_type == TYPE_SUMMARY:
                        part["summary"] = decode_summary(frame.payload)
                    elif frame.msg_type == TYPE_TEMPERATURES:
                        part["temperatures"] = tuple(
                            decode_temperatures(frame.payload)
                        )
                    elif frame.msg_type == TYPE_ALARM and len(frame.payload) == 8:
                        part["alarm_bits"] = decode_alarm_bits(frame.payload)
                    elif frame.msg_type == TYPE_MODEL:
                        part["model"] = decode_model(frame.payload)
                    elif frame.msg_type == TYPE_RELAY:
                        part["relay_routes"] = decode_routes(frame.payload)
                    elif frame.msg_type == TYPE_SWITCH:
                        # is_master comes from the position word, not from here:
                        # both agree, and position is present on every frame.
                        part["switch_routes"] = decode_routes(frame.payload)
                    else:
                        continue
                except (ValueError, IndexError, struct.error):
                    self._logger.debug(
                        "%s: malformed type-0x%02x payload (%d bytes), skipping",
                        frame.serial,
                        frame.msg_type,
                        len(frame.payload),
                    )
                    continue

                # A battery only counts as complete once it has *both* the pack
                # summary and its cells. Requiring only one of them exits far
                # too early: type-0x00 summaries arrive several times more
                # often than type-0x05 cell frames, so `expect` would be
                # satisfied by summaries alone and return readings with no cell
                # data at all.
                if expect and sum(1 for p in parts.values() if _complete(p)) >= expect:
                    enough.set()

        client = await self._async_connect()
        try:
            await client.start_notify(NOTIFY_CHAR, _on_notify)

            if self._serial:
                request = build_request(self._serial)
                await client.write_gatt_char(REQUEST_CHAR, request, response=True)
                self._logger.debug("%s: sent request %s", self.address, request.hex())

            try:
                await asyncio.wait_for(enough.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass

            try:
                await client.stop_notify(NOTIFY_CHAR)
            except Exception:  # noqa: BLE001 -- teardown must not mask results
                self._logger.debug("%s: stop_notify failed, ignoring", self.address)
        finally:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001 -- ditto
                self._logger.debug("%s: disconnect failed, ignoring", self.address)

        # Partial batteries are still returned -- a unit that sent a summary but
        # no cells before the timeout is more useful than nothing.
        batteries = {
            serial: BatteryReading(serial=serial, **part)
            for serial, part in parts.items()
            if part.get("summary") or part.get("cell_voltages_mv")
        }
        if not batteries:
            raise TensiteNoDataError(
                f"{self.address}: connected but no battery frames arrived within "
                f"{timeout:.0f}s"
            )

        master = next(
            (s for s, b in batteries.items() if b.is_master), self._serial
        )
        if stats.rejected:
            # Not fatal on its own -- a truncated frame at the tail of a
            # session is normal -- but a sustained ratio means the parser and
            # the firmware disagree about framing, which this protocol hides
            # well. Surfaced on the reading so callers can alert on it.
            self._logger.debug(
                "%s: %d/%d frame candidates rejected (%.1f%%): %s",
                self.address,
                stats.rejected,
                stats.frames + stats.rejected,
                stats.reject_ratio * 100,
                f"crc={stats.crc_failures} len={stats.length_mismatches} "
                f"escape={stats.bad_escapes} truncated={stats.truncated}",
            )
        return ClusterReading(
            address=self.address,
            master_serial=master,
            batteries=batteries,
            stats=stats,
        )
