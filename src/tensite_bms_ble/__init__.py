"""Read Tensite / UhomeEnergy battery clusters over BLE.

Connecting to a cluster's master battery relays frames for every battery in the
bank. The library is deliberately split so the Bluetooth layer can be driven by
Home Assistant's shared scanner:

    from homeassistant.components import bluetooth
    from tensite_bms_ble import TensiteClusterClient

    device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
    reading = await TensiteClusterClient(device, serial=serial).async_read(expect=4)

Standalone, with no scanner supplied, it falls back to plain bleak.
"""

from __future__ import annotations

from .client import (
    DiscoveredCluster,
    TensiteClusterClient,
    TensiteError,
    TensiteNoDataError,
    async_discover_clusters,
    is_tensite_advertisement,
)
from .const import (
    MANUFACTURER_DATA_START,
    MANUFACTURER_ID,
    NOTIFY_CHAR,
    REQUEST_CHAR,
    SERIAL_MARKER,
    SERVICE_UUID,
)
from .models import BatteryReading, ClusterReading
from .protocol import Frame, build_request, crc16_arc, decode_cells, parse_frames

__version__ = "0.1.0"

__all__ = [
    "BatteryReading",
    "ClusterReading",
    "DiscoveredCluster",
    "Frame",
    "MANUFACTURER_DATA_START",
    "MANUFACTURER_ID",
    "NOTIFY_CHAR",
    "REQUEST_CHAR",
    "SERIAL_MARKER",
    "SERVICE_UUID",
    "TensiteClusterClient",
    "TensiteError",
    "TensiteNoDataError",
    "__version__",
    "async_discover_clusters",
    "build_request",
    "crc16_arc",
    "decode_cells",
    "is_tensite_advertisement",
    "parse_frames",
]
