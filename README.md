# tensite-bms-ble

Read Tensite / UhomeEnergy BMS battery clusters over Bluetooth LE.

Connecting to a cluster's **master** battery relays frames for every battery in
the bank, so one connection covers the whole cluster. No authentication,
pairing, or handshake is required.

Works standalone from the command line, and is built to be driven by Home
Assistant's shared Bluetooth stack — see [Home Assistant compatibility](#home-assistant-compatibility).

## Install

```bash
pip install tensite-bms-ble
```

## CLI

```bash
# List batteries in range
tensite-bms-ble --scan

# Read the whole cluster, stopping as soon as all four have reported
tensite-bms-ble --serial 1417725SLKOPGG08146 --expect 4

# Machine-readable
tensite-bms-ble --serial 1417725SLKOPGG08146 --expect 4 --json
```

```
=== cluster C01 @ EDBA9394-9198-AE04-407F-5B64F1F8D8F0 ===
4 batteries   52.43 V mean stack   3065-3305 mV   delta 240 mV

1417607SLKOPGG08313  [C01/P02]
  01: 3.278 V   02: 3.293 V   03: 3.284 V   04: 3.288 V
  ...
  13: 3.065 V   14: 3.272 V   15: 3.272 V   16: 3.289 V
  min 3065 mV   max 3305 mV   delta 240 mV   sum 52.43 V
```

## Library

```python
from tensite_bms_ble import TensiteClusterClient, async_discover_clusters

found = await async_discover_clusters()
master = found[0]

client = TensiteClusterClient(master.device, serial=master.serial)
reading = await client.async_read(expect=4)

for serial, battery in reading.batteries.items():
    print(serial, battery.position_label, battery.min_cell_mv, battery.max_cell_mv)
```

`ClusterReading` → `BatteryReading` mirrors the hardware: one gateway, several
batteries, sixteen cells each.

### Streaming

`async_read` connects, listens and disconnects — fine for a one-shot read, but
it pays ~12 s of connection setup for a few seconds of data. The gateway streams
unprompted once notifications are enabled, so a held connection gets everything
the vendor app sees:

```python
from tensite_bms_ble import TensiteClusterStream

stream = TensiteClusterStream(
    master.device,
    serial=master.serial,
    on_update=lambda reading: print(reading.battery_count, reading.min_cell_mv),
)
await stream.async_start()          # returns once connected
...
await stream.async_stop()           # frees the gateway for other apps
```

`on_update` fires as frames arrive — every battery in the bank reports cell
voltages about every 5 s, concurrently — coalesced to at most one call per
`update_throttle` seconds (default 2). A dropped connection is retried with
backoff until `async_stop`.

Measured on a 182-second capture of the vendor app: all four batteries emitted
cell frames at a median 5.1 s gap, and kept doing so for 81 s after the app's
last write. The stream sustains itself; the link-test frame sent every 60 s is
precautionary, matching the ~79 s gap between the app's own writes.

## Home Assistant compatibility

Bluetooth work inside Home Assistant has rules, and this library follows them
so it can be embedded directly. Per the
[HA Bluetooth docs](https://developers.home-assistant.io/docs/bluetooth/):

- **It never creates a scanner when you supply one.** Home Assistant hands out
  a shared, adapter-aware scanner; running a second is expensive and breaks
  when adapter settings change. Pass it in:

  ```python
  from homeassistant.components import bluetooth

  scanner = bluetooth.async_get_scanner(hass)
  found = await async_discover_clusters(scanner=scanner)
  ```

- **It prefers a resolved `BLEDevice` over an address**, so Home Assistant can
  supply one from its own cache without scanning at all:

  ```python
  device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
  reading = await TensiteClusterClient(device, serial=serial).async_read(expect=4)
  ```

- **Connections go through `bleak_retry_connector.establish_connection`**,
  which absorbs the transient first-attempt failures that are normal on BLE.
- **A `BleakClient` is never reused between connections** — a fresh one per read.
- **Connection timeouts are clamped to ≥10 s**, because BlueZ has to resolve
  services on a first connection.

Pass `connector=` to override connection establishment entirely.

## Caveats

**One central at a time.** The ESP32 gateway accepts a single BLE connection.
Stop anything else talking to it — another script, a batmon-ha add-on — or
connects will fail.

**Advertising is intermittent.** A battery can be missing from any single scan.
The CLI retries (`--scan-attempts`); library callers should too.

**Read the serial from the advertisement, not `BLEDevice.name`.** On macOS the
latter returns CoreBluetooth's cached GATT Device Name, which is `ESP32` for
every unit in the bank. `async_discover_clusters` handles this.

**Every battery reports concurrently, not in rotation.** Each unit sends its own
cell frames roughly every 5 s, all of them at once — the bank is not
round-robined, which earlier notes here claimed. A short listening window can
still miss units simply because it is shorter than that cadence. With
`async_read`, pass `expect=` to return as soon as the whole bank has reported
instead of waiting out the timeout; with `TensiteClusterStream` the question does
not arise.

## What is and isn't decoded

Decoded and verified against the vendor app:

- **Per-cell voltages** (16 per battery) — exact match with the app's Cell
  Voltage tab, on live hardware.
- Battery serial, cluster/position, master identification.

Not decoded yet: **pack voltage, current, SOC, and the 4–6 pack temperature
sensors**. Those live in frame types `0x00` and `0x32`, which additionally
carry a 3-byte trailer beginning `0xBD` that satisfies no CRC variant tried so
far. `BatteryReading.total_voltage` sums the cells as a stand-in for pack
voltage; in practice it tracks the app's reading closely, but it is derived,
not reported.

## Protocol

Frames are `5E … 7E`, checksummed with **CRC-16/ARC** over the body excluding
the leading `0x5E`. Payloads are XOR-masked with a fixed 32-byte keystream.

The frames that appear "static" — type `0x01` and type `0x51` — are the device
handing out that keystream, not telemetry. Decoding type `0x01` as pack
voltage/current/SOC yields a plausible-looking but entirely fictional reading
that never changes.

Cell voltages come from type `0x05`: XOR the 32-byte payload with the keystream
and read 16 big-endian `uint16` millivolt values.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

Tests run without hardware. The protocol fixtures are real captured bytes
checked against vendor-app screenshots taken at the same second, not invented
values.

## License

MIT
