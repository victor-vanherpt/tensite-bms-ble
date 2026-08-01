"""Data models for a cluster reading.

The hierarchy mirrors the hardware: one BLE gateway (the cluster master)
relays frames for every battery in its bank, and each battery reports 16 cells.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .const import CELL_MV_MAX, CELL_MV_MIN
from .protocol import format_position

__all__ = ["BatteryReading", "ClusterReading"]


@dataclass(frozen=True, slots=True)
class BatteryReading:
    """One battery's most recent decoded state."""

    serial: str
    #: Raw position word from the frame, e.g. 0x01A0.
    position: int
    #: 16 cell voltages in millivolts, in cell order.
    cell_voltages_mv: tuple[int, ...]
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    @property
    def position_label(self) -> str:
        """Position as the vendor app renders it, e.g. ``C01/PA0``."""
        return format_position(self.position)

    @property
    def cluster_id(self) -> int:
        """Cluster number this battery belongs to."""
        return self.position >> 8

    @property
    def is_master(self) -> bool:
        """Whether this battery is the bank's gateway (position 0xA0)."""
        return self.position & 0xFF == 0xA0

    @property
    def cell_count(self) -> int:
        return len(self.cell_voltages_mv)

    @property
    def min_cell_mv(self) -> int:
        return min(self.cell_voltages_mv)

    @property
    def max_cell_mv(self) -> int:
        return max(self.cell_voltages_mv)

    @property
    def delta_mv(self) -> int:
        """Spread between the weakest and strongest cell -- the balance metric."""
        return self.max_cell_mv - self.min_cell_mv

    @property
    def total_voltage(self) -> float:
        """Sum of the cells in volts.

        This is the series stack voltage derived from the cells, not a directly
        reported pack voltage -- the frame carrying pack voltage is not decoded
        yet. In practice it tracks the app's reported pack voltage closely.
        """
        return sum(self.cell_voltages_mv) / 1000.0

    @property
    def implausible_cells(self) -> tuple[int, ...]:
        """1-based indices of cells outside the LiFePO4 sanity band."""
        return tuple(
            i + 1
            for i, mv in enumerate(self.cell_voltages_mv)
            if not CELL_MV_MIN <= mv <= CELL_MV_MAX
        )


@dataclass(frozen=True, slots=True)
class ClusterReading:
    """Everything gathered from one connection to a cluster master."""

    #: BLE address (or platform UUID on macOS) of the master we connected to.
    address: str
    #: Serial of the master, when known.
    master_serial: str | None
    batteries: dict[str, BatteryReading]
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    @property
    def battery_count(self) -> int:
        return len(self.batteries)

    @property
    def cluster_id(self) -> int | None:
        """Cluster number, taken from any battery that reported one."""
        for battery in self.batteries.values():
            return battery.cluster_id
        return None

    @property
    def total_voltage(self) -> float | None:
        """Mean stack voltage across the bank.

        The batteries are wired in parallel, so their voltages should agree
        closely; averaging smooths per-unit measurement noise.
        """
        if not self.batteries:
            return None
        return sum(b.total_voltage for b in self.batteries.values()) / len(
            self.batteries
        )

    @property
    def min_cell_mv(self) -> int | None:
        if not self.batteries:
            return None
        return min(b.min_cell_mv for b in self.batteries.values())

    @property
    def max_cell_mv(self) -> int | None:
        if not self.batteries:
            return None
        return max(b.max_cell_mv for b in self.batteries.values())

    @property
    def delta_mv(self) -> int | None:
        """Spread across every cell in the cluster."""
        if self.min_cell_mv is None or self.max_cell_mv is None:
            return None
        return self.max_cell_mv - self.min_cell_mv
