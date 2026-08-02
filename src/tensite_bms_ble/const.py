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

#: Pack telemetry: voltage, current, SOC, cell extremes, temperature extremes.
TYPE_SUMMARY = 0x00

#: Fault/alarm bitfield, 8 bytes. Every bit is zero in a healthy pack, which
#: is precisely why this frame looked like something else for so long: its
#: *masked* bytes are then identical to the keystream, and reading them as
#: pack telemetry produced a plausible-looking but entirely fictional value
#: that never changed. The keystream was recoverable from it exactly because
#: the plaintext is zero.
TYPE_ALARM = 0x01

#: Kept as an alias: the request frame the vendor app sends uses this same
#: message type, and build_request() addresses it.
TYPE_KEYSTREAM = TYPE_ALARM

#: Relay states -- the vendor app's "Relay"/"Relé" tab. One byte per four
#: routes, two bits each. The app registers this as message 0x1002 -> RTRelay.
#: Constant 0x01 in every capture (route 1 active, routes 2-4 not).
TYPE_RELAY = 0x02

#: Alias: this was read as a heartbeat before the message registry identified
#: it, and the name is kept so existing callers keep working.
TYPE_HEARTBEAT = TYPE_RELAY

#: Switch states -- the app's "Switching value"/"Valor de conmutación" tab.
#: Same layout as TYPE_RELAY; message 0x1003 -> RTSwitch. Reads 0xFF on the
#: bank master (all four routes = 3) and 0x00 on the others, which is why this
#: doubles as the master/slave indicator -- see decode_is_master().
TYPE_SWITCH = 0x03

#: Alias for the master/slave use of the switch frame.
TYPE_ROLE = TYPE_SWITCH

#: 16 x uint16 BE cell millivolts, XOR-obfuscated.
TYPE_CELLS = 0x05

#: One byte per pack temperature sensor. Four or six depending on the model.
TYPE_TEMPERATURES = 0x21

#: ASCII model/firmware string, e.g. "AB4850/100_2.0".
TYPE_MODEL = 0x24

#: Bank roster: a count byte followed by that many 19-byte ASCII serials.
#: The app calls it RTTopology. Every battery sends a 20-byte form naming
#: itself; the master also sends a 77-byte form listing the whole bank.
TYPE_TOPOLOGY = 0x32

#: Kept: this frame was called the identity frame before it was decoded.
TYPE_IDENTITY = TYPE_TOPOLOGY

#: Byte stuffing, HDLC-style with *two* flags. Both framing bytes are escaped
#: by the value one below them, followed by a code:
#:
#:     <prefix> 01  ->  prefix + 1   (the flag byte itself)
#:     <prefix> 02  ->  prefix       (a literal escape byte)
#:
#: so 0x7E arrives as ``7D 01``, 0x5E as ``5D 01``, and literal 0x7D / 0x5D as
#: ``7D 02`` / ``5D 02``.
#:
#: Getting the 0x5D half wrong is quietly catastrophic rather than noisy: the
#: frame still looks well-formed, just shifted by a byte from the escape
#: onward. Cell frames are the ones that suffer, because whether a payload
#: contains a masked 0x5E depends on the actual cell voltage -- around
#: 3355 mV every single cell frame contains one, and cell readings disappear
#: entirely while every other frame type keeps working.
ESCAPE_PREFIXES = frozenset({0x5D, 0x7D})
ESCAPE_LITERAL = 0x02  # <prefix> 02 -> prefix
ESCAPE_FLAG = 0x01  # <prefix> 01 -> prefix + 1

#: Temperatures are a raw *unsigned* byte with a 50 degree offset, so the
#: representable range is -50..205 C. Confirmed in the vendor app's machine
#: code: RTTemperature.setData() stores the bytes raw, and the offset is applied
#: only at display time (``sub x3, x1, #0x32``), which is the sole subtraction
#: of 50 anywhere in the app.
TEMPERATURE_OFFSET = 50

#: Two decoded values are sentinels rather than measurements: raw 0x00 and 0x14.
#: Both are reported verbatim, exactly as the vendor app displays them.
#:
#: What they *mean* stays an open question, and the app cannot answer it: its
#: temperature page has no sentinel logic at all. It renders "-" only when a
#: value is absent (the payload carried fewer temperatures than the page has
#: rows) and otherwise prints raw-50 unconditionally. There is no comparison
#: against 20, 30 or 50 and no -50/-30 constant anywhere in the binary. See
#: is_sentinel_temperature().
#:
#: Note these are *specific values*, not "anything negative". A pack really can
#: sit below freezing, and -5 C in winter is a measurement.
TEMPERATURE_SENTINELS = frozenset({-50, -30})

#: Current uses offset binary: 0x8000 is zero, above is discharge.
CURRENT_ZERO = 0x8000

#: Below this magnitude the pack is treated as idle rather than charging or
#: discharging. The BMS reports current in 0.1 A steps, so anything under a
#: couple of steps is measurement noise, not flow.
IDLE_CURRENT_A = 0.3

PROTOCOL_VERSION = 0x0207

#: Cluster 01 / position A0 -- the master. Requests are addressed here.
POSITION_MASTER = 0x01A0

#: The payload mask is not a table -- it is a linear congruential generator,
#: read out of the vendor app at ``Msg`` 0x9609ec::
#:
#:     msub x10, x12, x8, x9    ; state mod M
#:     mul  x9,  x10, x6        ; * A
#:     add  w10, w9,  w3        ; + C, truncated to 32 bits
#:     lsr  w12, w10, #0x14     ; byte = state >> 20
#:     and  x13, x12, x2        ;      & 0xFF
#:
#: Seeded at 0, it reproduces the mask exactly, which means there is no length
#: limit: any payload can be unmasked, however long.
#:
#: This replaced a captured 39-byte table. Thirty-six of its bytes were right;
#: the last three were wrong, because they had been derived from the topology
#: frame on the assumption that its plaintext began with the sender's serial
#: twice. It does not -- the second entry is the next battery in the bank, and
#: those serials differ only in their final three characters. The generator
#: settles it, and nothing had been decoded wrongly in practice because no
#: other payload reaches 37 bytes.
KEYSTREAM_MODULUS = 689854231
KEYSTREAM_MULTIPLIER = 340100002
KEYSTREAM_INCREMENT = 778321986
KEYSTREAM_SHIFT = 20
KEYSTREAM_SEED = 0

MAX_BATTERIES = 8

CELL_COUNT = 16

#: Plausibility band for a LiFePO4 cell, in millivolts. Used only to flag
#: suspicious decodes -- values outside it are still reported.
CELL_MV_MIN = 2000
CELL_MV_MAX = 3800

#: Relay and switch frames pack four routes into every byte, two bits each, and
#: the vendor app's model tops out at 16 named routes (Route1..Route16).
ROUTES_PER_BYTE = 4
MAX_ROUTES = 16

#: The route value the app renders as active. Established by pairing the iOS
#: capture with the screenshot taken from it: the master's relay frame reads
#: 0x01 (route 1 = 1, routes 2-4 = 0) and the app's Relay tab highlights route 1
#: alone. Values 0 and 3 both render unhighlighted, so only 1 is pinned; see
#: decode_routes().
ROUTE_ACTIVE = 1
