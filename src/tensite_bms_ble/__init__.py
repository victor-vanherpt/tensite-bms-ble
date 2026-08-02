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
from .alarms import (
    ALARM_SLOTS,
    ALARM_SLOTS_BY_KEY,
    AlarmLevel,
    AlarmSlot,
    active_alarms,
    decode_alarms,
    unmapped_bits,
)
from .models import BatteryReading, ClusterReading, merge_readings
from .protocol import (
    Frame,
    ParseStats,
    Summary,
    Topology,
    build_request,
    crc16_arc,
    decode_alarm_bits,
    decode_cells,
    decode_is_master,
    decode_routes,
    decode_model,
    decode_topology,
    decode_summary,
    decode_temperatures,
    is_sentinel_temperature,
    parse_frames,
    unmask,
)

__version__ = "0.7.0"

__all__ = [
    "ALARM_SLOTS",
    "ALARM_SLOTS_BY_KEY",
    "AlarmLevel",
    "AlarmSlot",
    "active_alarms",
    "decode_alarms",
    "unmapped_bits",
    "BatteryReading",
    "ClusterReading",
    "DiscoveredCluster",
    "Frame",
    "ParseStats",
    "MANUFACTURER_DATA_START",
    "MANUFACTURER_ID",
    "NOTIFY_CHAR",
    "REQUEST_CHAR",
    "SERIAL_MARKER",
    "SERVICE_UUID",
    "Summary",
    "Topology",
    "TensiteClusterClient",
    "TensiteError",
    "TensiteNoDataError",
    "__version__",
    "async_discover_clusters",
    "build_request",
    "crc16_arc",
    "decode_alarm_bits",
    "decode_cells",
    "decode_is_master",
    "decode_routes",
    "decode_model",
    "decode_topology",
    "decode_summary",
    "decode_temperatures",
    "is_sentinel_temperature",
    "is_tensite_advertisement",
    "merge_readings",
    "parse_frames",
    "unmask",
]
