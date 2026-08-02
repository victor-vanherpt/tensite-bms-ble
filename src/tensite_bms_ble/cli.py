"""Command-line entry point: ``tensite-bms-ble``.

Standalone use only -- it creates its own scanner. Inside Home Assistant the
library is driven through :class:`~tensite_bms_ble.client.TensiteClusterClient`
with a device resolved from Home Assistant's own Bluetooth cache.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .client import (
    DiscoveredCluster,
    TensiteClusterClient,
    TensiteError,
    async_discover_clusters,
)
from .const import DEFAULT_LISTEN_TIMEOUT, SERIAL_MARKER
from .models import ClusterReading

_LOGGER = logging.getLogger("tensite_bms_ble")


async def _resolve(
    address: str | None, serial: str | None, timeout: float, attempts: int
) -> DiscoveredCluster:
    """Scan for the requested battery, retrying because advertising is intermittent."""
    wanted = address or serial
    for attempt in range(1, attempts + 1):
        suffix = f" (attempt {attempt}/{attempts})" if attempt > 1 else ""
        print(f"scanning {timeout:.0f}s{suffix} ...", file=sys.stderr)
        found = await async_discover_clusters(timeout=timeout)
        for cluster in found:
            print(
                f"  {cluster.address}  {cluster.serial or '<unknown serial>'}  "
                f"{cluster.rssi} dBm",
                file=sys.stderr,
            )
        if wanted:
            match = next(
                (c for c in found if wanted in (c.address, c.serial)), None
            )
            if match:
                return match
            print(f"  {wanted} not in this scan", file=sys.stderr)
            continue
        if found:
            if len(found) > 1:
                print(
                    f"note: {len(found)} batteries advertising; using the "
                    f"strongest ({found[0].name}). Pass --serial to choose the "
                    "cluster master explicitly.",
                    file=sys.stderr,
                )
            return found[0]
    raise TensiteError(
        f"{wanted or 'no Tensite battery'} not found after {attempts} scans. "
        "Check it is powered and in range, and that nothing else is holding "
        "the gateway's single BLE connection slot."
    )


def _fmt(value, unit: str, spec: str = ".1f") -> str:
    return "--" if value is None else f"{value:{spec}}{unit}"


def _print_human(reading: ClusterReading) -> None:
    cluster = f"C{reading.cluster_id:02d}" if reading.cluster_id is not None else "?"
    print(f"\n=== cluster {cluster} @ {reading.address} ===")
    print(
        f"{reading.battery_count} batteries   "
        f"{_fmt(reading.total_voltage, ' V', '.2f')}   "
        f"{_fmt(reading.current, ' A')}   "
        f"{_fmt(reading.power, ' W', '.0f')}   "
        f"{_fmt(reading.soc, ' %')}"
    )
    print(
        f"cells {reading.min_cell_mv}-{reading.max_cell_mv} mV "
        f"(delta {reading.delta_mv} mV)   "
        f"temps {_fmt(reading.min_temperature, ' C', 'd')} to "
        f"{_fmt(reading.max_temperature, ' C', 'd')}"
    )
    for serial in sorted(reading.batteries):
        battery = reading.batteries[serial]
        marker = "  (master)" if battery.is_master else ""
        model = f"  {battery.model}" if battery.model else ""
        print(f"\n{serial}  [{battery.position_label}]{marker}{model}")
        print(
            f"  {_fmt(battery.voltage, ' V', '.1f')}   "
            f"{_fmt(battery.current, ' A')}   "
            f"{_fmt(battery.power, ' W', '.0f')}   "
            f"{_fmt(battery.soc, ' %')}"
        )
        cells = battery.cell_voltages_mv
        for row in range(0, len(cells), 4):
            print(
                "  "
                + "   ".join(
                    f"{n + 1:02d}: {cells[n] / 1000:.3f} V"
                    for n in range(row, min(row + 4, len(cells)))
                )
            )
        if cells:
            print(
                f"  cells {battery.min_cell_mv}-{battery.max_cell_mv} mV   "
                f"delta {battery.delta_mv} mV   "
                f"sum {_fmt(battery.cell_sum_voltage, ' V', '.2f')}"
            )
        if battery.temperatures:
            shown = ", ".join(
                "fault" if t is None else f"{t}C" for t in battery.temperatures
            )
            print(f"  pack temps: {shown}")
        if battery.relay_routes:
            print(
                "  relays: "
                + ", ".join(
                    f"{n}={v}" for n, v in enumerate(battery.relay_routes, 1)
                )
            )
        if battery.implausible_cells:
            print(f"  !! implausible cells: {battery.implausible_cells}")
        for slot, level in battery.active_alarms:
            print(f"  !! {slot.category} -> {slot.label}: Level{level} Fault")
        if battery.unmapped_alarm_bits:
            # Bits outside the 29 the vendor app itself parses.
            print(
                f"  !! unrecognised alarm bits: "
                f"0x{battery.unmapped_alarm_bits:016x}"
            )


def _to_dict(reading: ClusterReading) -> dict:
    return {
        "address": reading.address,
        "cluster_id": reading.cluster_id,
        "master_serial": reading.master_serial,
        "updated_at": reading.updated_at.isoformat(),
        "battery_count": reading.battery_count,
        "voltage": reading.total_voltage,
        "current": reading.current,
        "power": reading.power,
        "soc": reading.soc,
        "min_cell_mv": reading.min_cell_mv,
        "max_cell_mv": reading.max_cell_mv,
        "delta_mv": reading.delta_mv,
        "min_temperature": reading.min_temperature,
        "max_temperature": reading.max_temperature,
        "batteries": {
            serial: {
                "position": battery.position,
                "position_label": battery.position_label,
                "is_master": battery.is_master,
                "model": battery.model,
                "voltage": battery.voltage,
                "current": battery.current,
                "power": battery.power,
                "soc": battery.soc,
                "cell_voltages_mv": list(battery.cell_voltages_mv),
                "min_cell_mv": battery.min_cell_mv,
                "max_cell_mv": battery.max_cell_mv,
                "delta_mv": battery.delta_mv,
                "cell_sum_voltage": battery.cell_sum_voltage,
                "temperatures": list(battery.temperatures),
                "min_temperature": battery.min_temperature,
                "max_temperature": battery.max_temperature,
                "faulty_temperature_sensors": battery.faulty_temperature_sensors,
                "implausible_cells": list(battery.implausible_cells),
                "relay_routes": list(battery.relay_routes),
                "switch_routes": list(battery.switch_routes),
                "alarm_bits": battery.alarm_bits_hex,
                "alarm_level": (
                    int(battery.alarm_level)
                    if battery.alarm_level is not None
                    else None
                ),
                "active_alarms": [
                    {
                        "key": slot.key,
                        "name": slot.name,
                        "category": slot.category,
                        "label": slot.label,
                        "level": int(level),
                    }
                    for slot, level in battery.active_alarms
                ],
            }
            for serial, battery in sorted(reading.batteries.items())
        },
    }


async def _run(args: argparse.Namespace) -> int:
    if args.scan:
        found = await async_discover_clusters(timeout=args.scan_timeout)
        if not found:
            print("no Tensite batteries found", file=sys.stderr)
            return 1
        for cluster in found:
            print(
                f"{cluster.address}  {cluster.serial or '<unknown serial>'}  "
                f"{cluster.rssi} dBm"
            )
        return 0

    target = await _resolve(
        args.address, args.serial, args.scan_timeout, args.scan_attempts
    )
    serial = target.serial if target.serial and SERIAL_MARKER in target.serial else None

    print(f"connecting to {target.address} ...", file=sys.stderr)
    client = TensiteClusterClient(
        target.device or target.address,
        serial=serial,
        connect_timeout=args.connect_timeout,
        listen_timeout=args.duration,
        logger=_LOGGER,
    )
    goal = f", stopping early at {args.expect}" if args.expect else ""
    print(f"listening up to {args.duration:.0f}s{goal} ...", file=sys.stderr)
    reading = await client.async_read(expect=args.expect or None)

    if args.json:
        print(json.dumps(_to_dict(reading), indent=2))
    else:
        _print_human(reading)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tensite-bms-ble",
        description="Read cell voltages from a Tensite battery cluster over BLE.",
    )
    parser.add_argument("--address", help="BLE address/UUID of the cluster master")
    parser.add_argument("--serial", help="19-character serial of the cluster master")
    parser.add_argument(
        "--expect",
        type=int,
        default=0,
        metavar="N",
        help="stop once N batteries have reported (0 = wait out --duration)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=DEFAULT_LISTEN_TIMEOUT,
        help=f"max seconds to listen (default {DEFAULT_LISTEN_TIMEOUT:.0f})",
    )
    parser.add_argument("--connect-timeout", type=float, default=20.0)
    parser.add_argument("--scan-timeout", type=float, default=8.0)
    parser.add_argument(
        "--scan-attempts",
        type=int,
        default=3,
        help="rescans before giving up on a requested device (default 3)",
    )
    parser.add_argument("--scan", action="store_true", help="list batteries and exit")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return asyncio.run(_run(args))
    except TensiteError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
