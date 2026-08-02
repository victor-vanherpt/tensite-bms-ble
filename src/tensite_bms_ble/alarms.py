"""The type-0x01 fault bitfield, decoded.

Every field in this module was read out of the vendor app's own machine code
rather than inferred from captures, because a single fault sample cannot pin
thirty alarms. The app is a Flutter release build; its Dart AOT snapshot was
recovered with blutter (snapshot ``1441d6b13b8623fa7fbf61433abebd31``, Dart
2.17.6) and two functions of ``bms_app/models/msg/msg_rt_alarm.dart`` gave the
whole answer:

``RTAlarm.setData()`` at 0x908b1c is the byte-to-field parser. It loads the
eight payload bytes one at a time (``ldrb wN, [x2, #0x17+i]``) and, for each,
extracts 2-bit values with ``lsr``/``and #3`` and stores them to fixed object
offsets. That is the authoritative statement of which byte and which bit-pair
feeds each alarm.

``RTAlarm.toJson()`` at 0x8c5504 names them: it emits a string constant
immediately before loading the matching field, so the field offsets recovered
above pair one-to-one with names.

Two things that inference had got wrong, and which the machine code settles:

* The layout is **not** a uniform four alarms per byte. Byte 0 uses only bits
  0-1, 2-3 and 6-7 -- bits 4-5 are skipped -- and byte 5 uses only bits 0-3.
  Twenty-nine alarms, not thirty-two. Assuming a regular grid shifts every
  alarm after byte 0 by one slot, which is exactly the error that made an
  earlier attempt disagree with the one known fault.
* Each alarm is a 2-bit **severity**, not a flag. ``routes/monitor_alarm.dart``
  renders values 1, 2 and 3 as "Level1 Fault", "Level2 Fault" and "Level3
  Fault"; 0 is no fault.

Checked against the only real fault available: battery 1417C25SLKOPGG08043
reported ``00 00 30 00 00 00 00 00``. Byte 2 bits 4-5 is CellVoltageUnder at
severity 3, and the app showed exactly *Cell Faults -> Voltage Under: Fault*.

The categories and display labels are the app's own, taken from the same alarm
page, so a reading here lines up row for row with what the app shows.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Final


class AlarmLevel(IntEnum):
    """Severity of a single alarm slot.

    The app has no wording for level 1 vs 2 vs 3 beyond "LevelN Fault", so
    neither do we; only 0 is known to mean healthy.
    """

    NONE = 0
    LEVEL1 = 1
    LEVEL2 = 2
    LEVEL3 = 3


@dataclass(frozen=True, slots=True)
class AlarmSlot:
    """Where one alarm lives in the bitfield, and what the app calls it."""

    #: The app's internal identifier, as emitted by ``RTAlarm.toJson()``.
    key: str
    #: The app's on-screen label. Not unique on its own -- "Temperature Over"
    #: appears under both Charge and Discharge -- so pair it with *category*.
    label: str
    #: The app's section heading on the alarm page.
    category: str
    #: Index into the eight-byte payload.
    byte: int
    #: Bit position of the low bit of this alarm's 2-bit value.
    shift: int
    #: Display name, where the app's label does not stand on its own.
    name_override: str | None = None

    @property
    def name(self) -> str:
        """Label qualified enough to stand alone, unique across all slots.

        The app's labels only make sense underneath their section heading:
        "Temperature Over" appears under both Charge and Discharge, and "Voltage
        Over" under Cell reads as the pack total unless it says so. Those three
        sections get their heading folded in; the rest are already unambiguous
        on their own ("Insulation Resistance Lower Fault", "Total Voltage
        Over"), and prefixing them would only produce "Power Power Voltage
        Over".
        """
        if self.name_override is not None:
            return self.name_override
        prefix = _NAME_PREFIXES.get(self.category)
        if prefix is None or self.label.startswith(prefix):
            return self.label
        return f"{prefix} {self.label}"


#: Sections whose labels need their heading folded into the display name; see
#: :attr:`AlarmSlot.name`.
_NAME_PREFIXES: Final[dict[str, str]] = {
    "Cell Faults": "Cell",
    "Charge Faults": "Charge",
    "Discharge Faults": "Discharge",
}

_POWER: Final = "Power Faults"
_SENSOR: Final = "Sensor&Link Faults"
_CELL: Final = "Cell Faults"
_CHARGE: Final = "Charge Faults"
_DISCHARGE: Final = "Discharge Faults"
_OTHER: Final = "Other Faults"

#: Every alarm the type-0x01 frame carries, in the app's display order.
#:
#: The app's alarm page also lists a "Heating Fault" (``HeatingFault``) row, but
#: ``RTAlarm`` has no field for it and ``setData()`` never populates one, so
#: this frame does not carry it. It is omitted rather than guessed at.
ALARM_SLOTS: Final[tuple[AlarmSlot, ...]] = (
    AlarmSlot("PowerVoltageOver", "Power Voltage Over", _POWER, 0, 0),
    AlarmSlot("PowerVoltageUnder", "Power Voltage Under", _POWER, 0, 2),
    # Byte 0 bits 4-5 are not read by setData().
    AlarmSlot(
        "InsulationResistanceLow",
        "Insulation Resistance Lower Fault",
        _POWER,
        0,
        6,
    ),
    AlarmSlot("CommunicationFault", "BMU Communication", _SENSOR, 1, 0),
    AlarmSlot("CLF_CellVoltage", "Cell Voltage Sensor Link", _SENSOR, 1, 2),
    AlarmSlot("CLF_T", "Temperature Sensor Link", _SENSOR, 1, 4),
    AlarmSlot("CurrentCollectorFault", "Current Sensor Link", _SENSOR, 1, 6),
    # The app spells this one "Battary"; kept verbatim so the key matches.
    AlarmSlot("BattaryCollectorFault", "Battary Sensor", _SENSOR, 4, 6),
    AlarmSlot(
        "CellVoltageDiffExcess", "Excessive Voltage Difference", _CELL, 2, 0
    ),
    AlarmSlot("CellVoltageOver", "Voltage Over", _CELL, 2, 2),
    AlarmSlot("CellVoltageUnder", "Voltage Under", _CELL, 2, 4),
    AlarmSlot("T_DiffExcess", "Temperature Difference", _CHARGE, 3, 2),
    AlarmSlot("T_Over", "Temperature Over", _CHARGE, 3, 4),
    AlarmSlot("T_Under", "Temperature Under", _CHARGE, 3, 6),
    AlarmSlot("OverCurrentCharge", "Current Over", _CHARGE, 4, 0),
    AlarmSlot(
        "Discharge_T_DiffExcess", "Temperature Difference", _DISCHARGE, 7, 0
    ),
    AlarmSlot("Discharge_T_Over", "Temperature Over", _DISCHARGE, 7, 2),
    AlarmSlot("Discharge_T_Under", "Temperature Under", _DISCHARGE, 7, 4),
    AlarmSlot("OverCurrentDischarge", "Current Over", _DISCHARGE, 4, 2),
    AlarmSlot("VoltageOver", "Total Voltage Over", _OTHER, 2, 6),
    AlarmSlot("VoltageUnder", "Total Voltage Under", _OTHER, 3, 0),
    # The app labels this bare "SOC" under its Other Faults heading, which is
    # too easily mistaken for the state-of-charge reading itself.
    AlarmSlot("SOCLower", "SOC", _OTHER, 4, 4, name_override="SOC Low"),
    AlarmSlot("VoltageDiffExcess", "Total Voltage Difference", _OTHER, 5, 0),
    AlarmSlot("CapacityInconsistency", "Capacity Inconsistency", _OTHER, 5, 2),
    # Byte 5 bits 4-7 are not read by setData().
    AlarmSlot("MOSTemperatureFault", "MOS Temperature Fault", _OTHER, 6, 0),
    AlarmSlot(
        "ContactRodTemperatureFault",
        "Contact Rod Temperature Fault",
        _OTHER,
        6,
        2,
    ),
    AlarmSlot("RelayOrMOSSticking", "Relay Or MOS Sticking", _OTHER, 6, 4),
    AlarmSlot("InternalFault", "Internal Fault", _OTHER, 6, 6),
    AlarmSlot(
        "InterPackBalancingFault", "Inter-pack Balancing Fault", _OTHER, 7, 6
    ),
)

ALARM_SLOTS_BY_KEY: Final[dict[str, AlarmSlot]] = {
    slot.key: slot for slot in ALARM_SLOTS
}

#: Length of the fault bitfield, in bytes.
ALARM_FIELD_LEN: Final = 8


def decode_alarms(bits: bytes) -> dict[str, AlarmLevel]:
    """Split the fault bitfield into per-alarm severities.

    Returns every known alarm, including the healthy ones, so callers can
    expose a stable set of entities rather than a set that changes shape
    whenever a fault clears. Slots past the end of a short *bits* are reported
    as :attr:`AlarmLevel.NONE`.
    """
    return {
        slot.key: AlarmLevel((bits[slot.byte] >> slot.shift) & 0b11)
        if slot.byte < len(bits)
        else AlarmLevel.NONE
        for slot in ALARM_SLOTS
    }


def active_alarms(bits: bytes) -> tuple[tuple[AlarmSlot, AlarmLevel], ...]:
    """Just the alarms that are firing, in the app's display order."""
    levels = decode_alarms(bits)
    return tuple(
        (slot, levels[slot.key])
        for slot in ALARM_SLOTS
        if levels[slot.key] is not AlarmLevel.NONE
    )


def unmapped_bits(bits: bytes) -> int:
    """Set bits that no known alarm accounts for.

    Byte 0 bits 4-5 and byte 5 bits 4-7 are never read by the app, and anything
    past byte 7 is outside the field. If those ever come up non-zero, this
    table is incomplete for that firmware -- worth surfacing rather than
    silently dropping.
    """
    covered = [0] * ALARM_FIELD_LEN
    for slot in ALARM_SLOTS:
        covered[slot.byte] |= 0b11 << slot.shift

    leftover = 0
    for index, value in enumerate(bits):
        mask = ~covered[index] if index < ALARM_FIELD_LEN else 0xFF
        leftover |= (value & mask) << (8 * index)
    return leftover
