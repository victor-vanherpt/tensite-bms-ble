"""Turning a stream of notification bytes into readings.

Split out of the client because there are two ways to consume the same stream
and they should not each grow their own copy of this: a one-shot read that
connects, listens and disconnects, and a held connection that keeps receiving.

A battery's state arrives as several frame types, independently and at
different rates -- on a held connection each battery emits cell voltages about
every five seconds, its summary rather more often, and the bank roster rarely.
So the pieces are accumulated per serial rather than replacing one another.
"""

from __future__ import annotations

import logging
import struct
from datetime import datetime, timezone
from typing import Any

from .const import (
    MSG_CLASS_REALTIME,
    MSG_RT_ALARM,
    MSG_RT_CELLS,
    MSG_RT_RELAY,
    MSG_RT_SUMMARY,
    MSG_RT_SWITCH,
    MSG_RT_TEMPERATURES,
    MSG_RT_TOPOLOGY,
    SERIAL_MARKER,
)
from .models import BatteryReading, ClusterReading
from .protocol import (
    ParseStats,
    decode_alarm_bits,
    decode_cells,
    decode_routes,
    decode_summary,
    decode_temperatures,
    decode_topology,
    parse_frames,
)

_LOGGER = logging.getLogger(__name__)

__all__ = ["ReadingAssembler"]


def _is_complete(part: dict[str, Any]) -> bool:
    """Whether a battery has reported everything a poll waits for.

    Both the pack summary *and* the cells. Requiring only one exits far too
    early: summaries arrive several times more often than cell frames, so a
    caller waiting for N batteries would be satisfied by summaries alone and
    get readings with no cell data at all.
    """
    return bool(part.get("summary")) and bool(part.get("cell_voltages_mv"))


class ReadingAssembler:
    """Accumulates decoded frames into a :class:`ClusterReading`.

    Stateful and cumulative: feed it bytes as they arrive and ask for a reading
    whenever one is wanted. Nothing is discarded between calls, so a held
    connection keeps refining the same picture rather than starting over.
    """

    def __init__(
        self,
        address: str,
        serial: str | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.address = address
        self.stats = ParseStats()
        self._serial = serial
        self._logger = logger or _LOGGER
        self._buffer = bytearray()
        self._parts: dict[str, dict[str, Any]] = {}
        #: Highest count any topology frame has claimed. Only the master sends
        #: the long form, and rarely, so this is kept once seen.
        self._roster = 0

    def feed(self, data: bytes) -> set[str]:
        """Consume notification bytes, returning the serials that changed.

        The buffer is deliberately kept across calls: a frame can be split
        across notifications, and the parser consumes only whole frames.
        """
        self._buffer.extend(data)
        touched: set[str] = set()

        for frame in parse_frames(self._buffer, self.stats):
            if (
                frame.msg_class != MSG_CLASS_REALTIME
                or SERIAL_MARKER not in frame.serial
            ):
                continue
            part = self._parts.setdefault(
                frame.serial, {"position": frame.position}
            )
            part["position"] = frame.position
            try:
                if frame.msg_id == MSG_RT_CELLS:
                    part["cell_voltages_mv"] = tuple(decode_cells(frame.payload))
                    part["cells_updated_at"] = datetime.now(tz=timezone.utc)
                elif frame.msg_id == MSG_RT_SUMMARY:
                    part["summary"] = decode_summary(frame.payload)
                elif frame.msg_id == MSG_RT_TEMPERATURES:
                    part["temperatures"] = tuple(decode_temperatures(frame.payload))
                elif frame.msg_id == MSG_RT_ALARM and len(frame.payload) == 8:
                    part["alarm_bits"] = decode_alarm_bits(frame.payload)
                elif frame.msg_id == MSG_RT_RELAY:
                    part["relay_routes"] = decode_routes(frame.payload)
                elif frame.msg_id == MSG_RT_SWITCH:
                    part["switch_routes"] = decode_routes(frame.payload)
                elif frame.msg_id == MSG_RT_TOPOLOGY:
                    topology = decode_topology(frame.payload)
                    if topology.is_plausible and topology.count > self._roster:
                        self._roster = topology.count
                        self._logger.debug(
                            "%s: topology says %d batteries (%d readable)",
                            frame.serial,
                            topology.count,
                            len(topology.serials),
                        )
                else:
                    self.stats.note_unhandled(frame.msg_id)
                    continue
            except (ValueError, IndexError, struct.error):
                self._logger.debug(
                    "%s: malformed %s payload (%d bytes), skipping",
                    frame.serial,
                    f"0x{frame.msg_id:04x}",
                    len(frame.payload),
                )
                continue
            touched.add(frame.serial)

        return touched

    @property
    def roster_count(self) -> int:
        """Batteries the bank says it holds, 0 if it has not said."""
        return self._roster

    def complete_count(self) -> int:
        """How many batteries have reported both a summary and their cells."""
        return sum(1 for part in self._parts.values() if _is_complete(part))

    def reading(self) -> ClusterReading | None:
        """The reading so far, or None if no battery has said anything usable.

        Partial batteries are included: one that sent a summary but no cells
        yet is more useful than nothing, and on a held connection its cells are
        seconds away.
        """
        batteries = {
            serial: BatteryReading(serial=serial, **part)
            for serial, part in self._parts.items()
            if part.get("summary") or part.get("cell_voltages_mv")
        }
        if not batteries:
            return None

        master = next(
            (s for s, b in batteries.items() if b.is_master), self._serial
        )
        return ClusterReading(
            address=self.address,
            master_serial=master,
            batteries=batteries,
            roster_count=self._roster or None,
            stats=self.stats,
        )
