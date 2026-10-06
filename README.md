# DRIP_PoC_PEE

>
A bench implementation of **drone Remote ID with DRIP authentication** (IETF
[RFC 9374](https://www.rfc-editor.org/rfc/rfc9374), [RFC 9575](https://www.rfc-editor.org/rfc/rfc9575), [RFC 9886](https://www.rfc-editor.org/rfc/rfc9886)) on top of **ASTM F3411-22a** Broadcast Remote ID for my Master Thesis.

An ESP32 plays the drone, or a fleet of up to three drones, broadcasting signed Remote ID messages over **Wi-Fi Beacon** or **Bluetooth Legacy**. You choose the radio at runtime. A second ESP32 captures the air, and Python tools on the PC decode the messages, verify the signatures and the endorsement chain, and report every error with the clause it violates.

```
 ESP32 #1 (broadcaster) ──air──▶ ESP32 #2 (sniffer) ──USB──▶ PC: capture file ──▶ Observer
   signed Remote ID              Wi-Fi or Bluetooth           (Python)            report / live map
```

---

## Repository layout

| Folder | Contents |
|---|---|
| `DRIP_Fleet_Broadcast/DRIP_Broadcast_RID/` | Broadcaster firmware (the "drone"): DRIP identities, endorsements, Manifests, Wi-Fi and Bluetooth transmission |
| `ObserverRealTime/` | Sniffer firmware (`DRIP_Sniffer.ino`) and the Python Observer: batch report, live map, flight map, test vectors |

Full documentation also includes:

- [`COMMANDS.md`](COMMANDS.md): every command for both boards and every script.
- [`PROJECT_MAP.md`](PROJECT_MAP.md): what each file does and how they connect.


---

## Requirements

**Hardware:** two ESP32 boards. Developed on *ESP32 Dev Module* (ESP32-D0WD-V3).

**Firmware (Arduino IDE):**
- `esp32` board package by Espressif, 3.3.x;
- the **Crypto** library by Rhys Weatherley;
- for **both** boards: *Tools → Partition Scheme → Huge APP (3MB No OTA/1MB SPIFFS)*.

**PC:** Python 3.13 or later, then:

```bash
pip install pyserial cryptography dnspython
```

`cryptography` is optional but makes signature checking much faster.
`dnspython` is only needed for the registry lookups.

---

## Quick start

**1. Flash the boards.** Upload `DRIP_Broadcast_RID.ino` to the first ESP32 and
`DRIP_Sniffer.ino` to the second. Both boot on Wi-Fi.

**2. Set up the broadcaster.** In its Serial Monitor (115200 baud), type:

```text
time <unix>     set the clock first - Unix seconds (UTC), e.g. from
                PowerShell: [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
fleet 3         three drones (or fleet 1)
radio bt        optional: switch to Bluetooth (1 drone max)
```

If you use Bluetooth, also type `radio bt` on the sniffer.

**3. Capture and watch live.** From `ObserverRealTime/`, replacing `COM3` with
the sniffer's port:

```bash
python run_live.py --port COM3
```

Then open <http://127.0.0.1:8080/> to see the drones on a map, each coloured by
its authentication state.

**4. Analyse a capture afterwards:**

```bash
python observer.py capture_YYYY-MM-DD_HHMM.txt      # full conformance report
python make_map.py capture_YYYY-MM-DD_HHMM.txt -o flight.html
```

**5. Self-test:** checks the Observer against known-good and known-bad
vectors. No board is needed.

```bash
python make_vectors.py --selftest
```

---

## Security note

All keys and identities in this repository are **test values**, hard-coded on purpose and therefore public. They must never be registered or used on a real aircraft.

 The broadcaster also holds its registry's signing keys so that it can endorse itself, which a real drone must never do. Secure key storage is necessary for a real drone. 

Details are in [`COMMANDS.md`](COMMANDS.md), section 1.9.
