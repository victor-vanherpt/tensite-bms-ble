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


def _print_human(reading: ClusterReading) -> None:
    cluster = f"C{reading.cluster_id:02d}" if reading.cluster_id is not None else "?"
    total = reading.total_voltage
    print(f"\n=== cluster {cluster} @ {reading.address} ===")
    print(
        f"{reading.battery_count} batteries   "
        f"{total:.2f} V mean stack   "
        f"{reading.min_cell_mv}-{reading.max_cell_mv} mV   "
        f"delta {reading.delta_mv} mV"
    )
    for serial in sorted(reading.batteries):
        battery = reading.batteries[serial]
        marker = "  (master)" if battery.is_master else ""
        print(f"\n{serial}  [{battery.position_label}]{marker}")
        cells = battery.cell_voltages_mv
        for row in range(0, len(cells), 4):
            print(
                "  "
                + "   ".join(
                    f"{n + 1:02d}: {cells[n] / 1000:.3f} V"
                    for n in range(row, min(row + 4, len(cells)))
                )
            )
        print(
            f"  min {battery.min_cell_mv} mV   max {battery.max_cell_mv} mV   "
            f"delta {battery.delta_mv} mV   sum {battery.total_voltage:.2f} V"
        )
        if battery.implausible_cells:
            print(f"  !! implausible cells: {battery.implausible_cells}")


def _to_dict(reading: ClusterReading) -> dict:
    return {
        "address": reading.address,
        "cluster_id": reading.cluster_id,
        "master_serial": reading.master_serial,
        "updated_at": reading.updated_at.isoformat(),
        "battery_count": reading.battery_count,
        "total_voltage": reading.total_voltage,
        "min_cell_mv": reading.min_cell_mv,
        "max_cell_mv": reading.max_cell_mv,
        "delta_mv": reading.delta_mv,
        "batteries": {
            serial: {
                "position": battery.position,
                "position_label": battery.position_label,
                "is_master": battery.is_master,
                "cell_voltages_mv": list(battery.cell_voltages_mv),
                "min_cell_mv": battery.min_cell_mv,
                "max_cell_mv": battery.max_cell_mv,
                "delta_mv": battery.delta_mv,
                "total_voltage": battery.total_voltage,
                "implausible_cells": list(battery.implausible_cells),
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
