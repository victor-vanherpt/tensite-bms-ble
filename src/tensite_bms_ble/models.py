"""Data models for a cluster reading.

The hierarchy mirrors the hardware: one BLE gateway (the cluster master)
relays frames for every battery in its bank, and each battery reports 16 cells.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .alarms import (
    AlarmLevel,
    AlarmSlot,
    decode_alarms,
    unmapped_bits,
)
from .alarms import active_alarms as _active_alarms
from .const import CELL_MV_MAX, CELL_MV_MIN, IDLE_CURRENT_A, ROUTE_ACTIVE
from .protocol import (
    ParseStats,
    Summary,
    format_position,
    is_sentinel_temperature,
)

__all__ = ["BatteryReading", "ClusterReading", "merge_readings"]


@dataclass(frozen=True, slots=True)
class BatteryReading:
    """One battery's most recent decoded state."""

    serial: str
    #: Raw position word from the frame, e.g. 0x01A0.
    position: int
    #: 16 cell voltages in millivolts, in cell order.
    cell_voltages_mv: tuple[int, ...] = ()
    #: Pack telemetry, when a type-0x00 frame has been seen.
    summary: Summary | None = None
    #: Per-sensor pack temperatures in C, exactly as the BMS reports them --
    #: including the -50 / -30 fault sentinels, matching the vendor app. Four
    #: or six depending on model. These are *pack* sensors, not per-cell.
    temperatures: tuple[int, ...] = ()
    #: Model string reported by the BMS, e.g. "AB4850/100_2.0".
    model: str | None = None
    #: Raw 8-byte fault bitfield from the type-0x01 frame. All zero means no
    #: fault; see :mod:`tensite_bms_ble.alarms` for the per-alarm breakdown.
    alarm_bits: bytes | None = None
    #: Relay route values (type 0x02), one per route, each 0-3. Four routes on
    #: this hardware. See decode_routes() -- 1 is the state the app highlights.
    relay_routes: tuple[int, ...] = ()
    #: Switch route values (type 0x03), same shape as relay_routes. Reads all
    #: 3 on the bank master and all 0 elsewhere.
    switch_routes: tuple[int, ...] = ()
    #: When the per-cell voltages were last actually received. Cell frames can
    #: lag or stop while pack telemetry keeps flowing, so a merged reading may
    #: carry cells much older than the rest of it -- this says how old.
    cells_updated_at: datetime | None = None
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    @property
    def voltage(self) -> float | None:
        """Pack voltage in volts, as reported by the BMS."""
        return self.summary.voltage if self.summary else None

    @property
    def current(self) -> float | None:
        """Current in amps, positive while discharging."""
        return self.summary.current if self.summary else None

    @property
    def soc(self) -> float | None:
        """State of charge, percent."""
        return self.summary.soc if self.summary else None

    @property
    def power(self) -> float | None:
        """Signed power in watts, positive while discharging."""
        return self.summary.power if self.summary else None

    @property
    def max_temperature(self) -> int | None:
        return self.summary.max_temperature if self.summary else None

    @property
    def min_temperature(self) -> int | None:
        return self.summary.min_temperature if self.summary else None

    @property
    def status(self) -> str | None:
        """``charging`` / ``discharging`` / ``idle``.

        Derived from the sign of the reported current, *not* decoded from a
        dedicated field. The vendor app shows a "Pack Status" string; whether
        it comes from a status byte we have not decoded, or is derived the same
        way, is unknown -- so treat this as a convenience, not as the BMS's own
        opinion.
        """
        if self.current is None:
            return None
        if self.current > IDLE_CURRENT_A:
            return "discharging"
        if self.current < -IDLE_CURRENT_A:
            return "charging"
        return "idle"

    @property
    def daily_charge_kwh(self) -> float | None:
        """Energy charged into this battery today."""
        return self.summary.daily_charge_kwh if self.summary else None

    @property
    def daily_discharge_kwh(self) -> float | None:
        """Energy discharged from this battery today."""
        return self.summary.daily_discharge_kwh if self.summary else None

    @property
    def faulty_temperature_sensors(self) -> int:
        """How many pack temperature sensors report a sentinel, not a reading."""
        return sum(1 for t in self.temperatures if is_sentinel_temperature(t))

    @property
    def healthy_temperatures(self) -> tuple[int, ...]:
        """Pack temperatures with the fault sentinels removed."""
        return tuple(t for t in self.temperatures if not is_sentinel_temperature(t))

    @property
    def has_cells(self) -> bool:
        return bool(self.cell_voltages_mv)

    @property
    def cells_age(self) -> float | None:
        """Seconds since the per-cell voltages were last received."""
        if self.cells_updated_at is None:
            return None
        return (
            datetime.now(tz=timezone.utc) - self.cells_updated_at
        ).total_seconds()

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
    def min_cell_mv(self) -> int | None:
        """Lowest cell, taken from the per-cell readings.

        Deliberately computed from the cell list rather than the BMS's own
        summary figure. The two often disagree -- see
        :attr:`reported_min_cell_mv` -- and only this one is guaranteed
        consistent with the 16 individual cell values.
        """
        if self.cell_voltages_mv:
            return min(self.cell_voltages_mv)
        return self.summary.min_cell_mv if self.summary else None

    @property
    def max_cell_mv(self) -> int | None:
        """Highest cell, taken from the per-cell readings."""
        if self.cell_voltages_mv:
            return max(self.cell_voltages_mv)
        return self.summary.max_cell_mv if self.summary else None

    @property
    def has_fault(self) -> bool | None:
        """Whether the BMS is reporting any fault at all.

        None until a type-0x01 frame has been seen. This is the part of the
        alarm frame that *is* established: zero means healthy, non-zero means
        the app would be showing at least one red "Fault".
        """
        if self.alarm_bits is None:
            return None
        return any(self.alarm_bits)

    @property
    def alarm_bits_hex(self) -> str | None:
        """The raw fault bitfield as hex, for diagnosing an unmapped alarm."""
        return self.alarm_bits.hex() if self.alarm_bits is not None else None

    @property
    def active_relays(self) -> tuple[bool, ...]:
        """Per relay route, whether it is in the state the app highlights.

        Only value 1 is established as active -- see decode_routes(). Values 0
        and 3 are both reported as not active because the app draws them
        identically, which is all the evidence supports.
        """
        return tuple(value == ROUTE_ACTIVE for value in self.relay_routes)

    @property
    def alarms(self) -> dict[str, AlarmLevel]:
        """Severity of every known alarm, healthy ones included.

        Empty until a type-0x01 frame has been seen, which is distinct from
        "every alarm is clear" -- callers that need to tell those apart should
        check :attr:`alarm_bits` for None.
        """
        if self.alarm_bits is None:
            return {}
        return decode_alarms(self.alarm_bits)

    @property
    def active_alarms(self) -> tuple[tuple[AlarmSlot, AlarmLevel], ...]:
        """Only the alarms that are firing, in the vendor app's order."""
        if self.alarm_bits is None:
            return ()
        return _active_alarms(self.alarm_bits)

    @property
    def alarm_level(self) -> AlarmLevel | None:
        """Highest severity across all alarms, or None if never reported."""
        if self.alarm_bits is None:
            return None
        firing = self.active_alarms
        return max((level for _, level in firing), default=AlarmLevel.NONE)

    @property
    def unmapped_alarm_bits(self) -> int:
        """Set bits no known alarm accounts for. Non-zero means this firmware
        reports something the app's own parser does not read."""
        if self.alarm_bits is None:
            return 0
        return unmapped_bits(self.alarm_bits)

    @property
    def weakest_cell(self) -> int | None:
        """1-based position of the lowest cell, as the BMS identifies it.

        The number worth alerting on: a cell that keeps showing up here is the
        one about to fail.
        """
        return self.summary.min_cell_index if self.summary else None

    @property
    def strongest_cell(self) -> int | None:
        """1-based position of the highest cell, as the BMS identifies it."""
        return self.summary.max_cell_index if self.summary else None

    @property
    def reported_min_cell_mv(self) -> int | None:
        """Lowest cell *as the BMS reports it* in the pack summary.

        This is the number the vendor app shows on its Overview screen, and it
        does not always agree with the minimum of the 16 per-cell values in the
        same poll -- on some units the two differ by tens of millivolts, and
        two different batteries have been seen reporting identical summary
        extremes. Which one the firmware intends is unknown; both are exposed
        so the discrepancy is visible rather than silently resolved.
        """
        return self.summary.min_cell_mv if self.summary else None

    @property
    def reported_max_cell_mv(self) -> int | None:
        """Highest cell as the BMS reports it. See :attr:`reported_min_cell_mv`."""
        return self.summary.max_cell_mv if self.summary else None

    @property
    def cell_extremes_disagree(self) -> bool:
        """Whether the summary's cell extremes differ from the cell list."""
        if not self.summary or not self.cell_voltages_mv:
            return False
        return (
            self.summary.min_cell_mv != min(self.cell_voltages_mv)
            or self.summary.max_cell_mv != max(self.cell_voltages_mv)
        )

    @property
    def delta_mv(self) -> int | None:
        """Spread between the weakest and strongest cell -- the balance metric."""
        lo, hi = self.min_cell_mv, self.max_cell_mv
        return None if lo is None or hi is None else hi - lo

    @property
    def cell_sum_voltage(self) -> float | None:
        """Cells summed, in volts.

        Kept alongside the BMS's own :attr:`voltage`: the two normally agree to
        within a few tens of millivolts, and a growing gap between them is a
        useful hint that a cell reading has gone bad.
        """
        if not self.cell_voltages_mv:
            return None
        return sum(self.cell_voltages_mv) / 1000.0

    @property
    def total_voltage(self) -> float | None:
        """Pack voltage, preferring the BMS's own reading over summed cells."""
        if self.summary:
            return self.summary.voltage
        return self.cell_sum_voltage

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
    #: What the parser rejected while building this reading.
    #: Battery count claimed by a type-0x32 topology frame, if one arrived.
    #: Authoritative about the *roster* -- how many batteries the master
    #: knows of -- which is not the same as how many answered this poll.
    #: None when no such frame was seen, which is the common case: only the
    #: vendor app's own session has ever elicited the long form.
    roster_count: int | None = None
    stats: ParseStats = field(default_factory=ParseStats)
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
        """Mean pack voltage across the bank.

        The batteries are wired in parallel, so their voltages should agree
        closely; averaging smooths per-unit measurement noise.
        """
        values = [
            b.total_voltage for b in self.batteries.values() if b.total_voltage
        ]
        return sum(values) / len(values) if values else None

    @property
    def current(self) -> float | None:
        """Total bank current in amps, positive while discharging.

        Summed, not averaged: the batteries are in parallel, so their currents
        add.
        """
        values = [b.current for b in self.batteries.values() if b.current is not None]
        return round(sum(values), 1) if values else None

    @property
    def power(self) -> float | None:
        """Total bank power in watts, positive while discharging."""
        values = [b.power for b in self.batteries.values() if b.power is not None]
        return round(sum(values), 1) if values else None

    @property
    def soc(self) -> float | None:
        """Mean state of charge across the bank, percent."""
        values = [b.soc for b in self.batteries.values() if b.soc is not None]
        return round(sum(values) / len(values), 1) if values else None

    @property
    def max_temperature(self) -> int | None:
        values = [
            b.max_temperature
            for b in self.batteries.values()
            if b.max_temperature is not None
        ]
        return max(values) if values else None

    @property
    def min_temperature(self) -> int | None:
        values = [
            b.min_temperature
            for b in self.batteries.values()
            if b.min_temperature is not None
        ]
        return min(values) if values else None

    @property
    def status(self) -> str | None:
        """Bank-level ``charging`` / ``discharging`` / ``idle``. Derived."""
        if self.current is None:
            return None
        if self.current > IDLE_CURRENT_A:
            return "discharging"
        if self.current < -IDLE_CURRENT_A:
            return "charging"
        return "idle"

    @property
    def daily_charge_kwh(self) -> float | None:
        """Energy charged into the whole bank today."""
        values = [
            b.daily_charge_kwh
            for b in self.batteries.values()
            if b.daily_charge_kwh is not None
        ]
        return round(sum(values), 1) if values else None

    @property
    def daily_discharge_kwh(self) -> float | None:
        """Energy discharged from the whole bank today."""
        values = [
            b.daily_discharge_kwh
            for b in self.batteries.values()
            if b.daily_discharge_kwh is not None
        ]
        return round(sum(values), 1) if values else None

    @property
    def has_fault(self) -> bool | None:
        """Whether any battery in the bank is reporting a fault."""
        flags = [
            b.has_fault for b in self.batteries.values() if b.has_fault is not None
        ]
        return any(flags) if flags else None

    @property
    def faulted_batteries(self) -> tuple[str, ...]:
        """Serials of the batteries currently reporting a fault."""
        return tuple(
            s for s, b in sorted(self.batteries.items()) if b.has_fault
        )

    @property
    def min_cell_mv(self) -> int | None:
        values = [
            b.min_cell_mv for b in self.batteries.values() if b.min_cell_mv is not None
        ]
        return min(values) if values else None

    @property
    def max_cell_mv(self) -> int | None:
        values = [
            b.max_cell_mv for b in self.batteries.values() if b.max_cell_mv is not None
        ]
        return max(values) if values else None

    @property
    def delta_mv(self) -> int | None:
        """Spread across every cell in the cluster."""
        if self.min_cell_mv is None or self.max_cell_mv is None:
            return None
        return self.max_cell_mv - self.min_cell_mv


def merge_readings(
    previous: ClusterReading | None, latest: ClusterReading
) -> ClusterReading:
    """Fold *latest* onto *previous*, carrying forward what it did not observe.

    The gateway round-robins the bank, so any single poll can miss part of it:
    a battery may report its pack summary but not its cells, or not appear at
    all. Taking each poll as the whole truth makes readings disappear and
    reappear between polls even though nothing is wrong.

    Fields are merged per battery, newest-wins, with an absent field falling
    back to the previous value. Batteries missing from *latest* entirely are
    retained -- a bank member that skipped one poll has not gone away.
    """
    if previous is None:
        return latest

    merged: dict[str, BatteryReading] = dict(previous.batteries)
    for serial, new in latest.batteries.items():
        old = merged.get(serial)
        if old is None:
            merged[serial] = new
            continue
        merged[serial] = BatteryReading(
            serial=serial,
            position=new.position or old.position,
            cell_voltages_mv=new.cell_voltages_mv or old.cell_voltages_mv,
            summary=new.summary or old.summary,
            temperatures=new.temperatures or old.temperatures,
            model=new.model or old.model,
            alarm_bits=(
                new.alarm_bits if new.alarm_bits is not None else old.alarm_bits
            ),
            relay_routes=new.relay_routes or old.relay_routes,
            switch_routes=new.switch_routes or old.switch_routes,
            updated_at=new.updated_at,
            # Carried forward with the cells it belongs to, so it keeps
            # reporting how stale those particular values are.
            cells_updated_at=(
                new.cells_updated_at
                if new.cell_voltages_mv
                else old.cells_updated_at
            ),
        )
    return ClusterReading(
        address=latest.address,
        master_serial=latest.master_serial or previous.master_serial,
        roster_count=latest.roster_count or previous.roster_count,
        batteries=merged,
        stats=latest.stats,
        updated_at=latest.updated_at,
    )
