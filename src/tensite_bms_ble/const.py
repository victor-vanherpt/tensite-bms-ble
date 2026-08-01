"""Protocol and BLE constants for Tensite / UhomeEnergy battery clusters."""

from __future__ import annotations

# --- BLE ---------------------------------------------------------------------

#: Main BMS service.
SERVICE_UUID = "0000a002-0000-1000-8000-00805f9b34fb"

#: Notify characteristic (value handle 0x38) -- the real-time frame stream.
NOTIFY_CHAR = "0000c305-0000-1000-8000-00805f9b34fb"

#: Write characteristic (value handle 0x36) -- framed requests go here.
#: Note this is c304, *not* c302: the vendor app never writes to c302.
REQUEST_CHAR = "0000c304-0000-1000-8000-00805f9b34fb"

#: Manufacturer ID in the advertisement; payload is ASCII "UHOME".
MANUFACTURER_ID = 0xE502
MANUFACTURER_DATA_START = b"UHOME"

#: Every serial seen so far contains this marker.
SERIAL_MARKER = "SLKOPGG"
SERIAL_LENGTH = 19

#: BlueZ needs time to resolve services on a first connection; Home Assistant
#: documentation requires a connection timeout of at least ten seconds.
MIN_CONNECT_TIMEOUT = 10.0
DEFAULT_CONNECT_TIMEOUT = 20.0

#: How long to listen for frames. The gateway round-robins the bank, emitting
#: each battery's frames roughly every 5-6 s, so a short window can miss units.
DEFAULT_LISTEN_TIMEOUT = 90.0

# --- Frame -------------------------------------------------------------------

FRAME_START = 0x5E
FRAME_END = 0x7E

#: 0x5E through the payload-length field inclusive.
HEADER_LEN = 36

#: Sanity cap when trusting a declared payload length.
MAX_PAYLOAD_LEN = 512

PROTO_APP = 0x50  # app -> device
PROTO_DEVICE = 0x10  # device -> app

#: Carries 8 bytes of the XOR keystream. Emphatically *not* pack telemetry --
#: decoding it as voltage/current/SOC yields a plausible-looking but entirely
#: fictional reading that never changes.
TYPE_KEYSTREAM = 0x01

#: 16 x uint16 BE cell millivolts, XOR-obfuscated.
TYPE_CELLS = 0x05

PROTOCOL_VERSION = 0x0207

#: Cluster 01 / position A0 -- the master. Requests are addressed here.
POSITION_MASTER = 0x01A0

#: The XOR keystream every payload is masked with. Recovered by XOR-ing a
#: type-0x05 payload against the 16 cell voltages the vendor app displayed for
#: the same battery at the same second. Constant across batteries, sessions and
#: days.
#:
#: Its first 8 bytes are exactly the "frozen" type-0x01 payload and its first 4
#: the "type-0x51 nonce" -- those frames are the device handing out the key,
#: which is why they never change.
KEYSTREAM = bytes.fromhex(
    "e6f8bbcbbc10ab6dca4953ac09844e0222c3a3056a3995a24a5d39877ebddc2c"
)

CELL_COUNT = 16

#: Plausibility band for a LiFePO4 cell, in millivolts. Used only to flag
#: suspicious decodes -- values outside it are still reported.
CELL_MV_MIN = 2000
CELL_MV_MAX = 3800
