# COMMANDS.md

Every command the bench accepts, grouped by what it drives. Written so the bench can be operated from this file alone, with no need to read source.

Last updated 05/10/2026.


---

## 0. Before anything else

### 0.1 Which folder to run in

| Folder | Holds | Use it for |
|---|---|---|
| `ObserverRealTime/` | the Observer, the tooling, the sniffer sketch and the live path | every command below |
| `DRIP_Fleet_Broadcast/DRIP_Broadcast_RID/` | the transmitter firmware | Section 1 only |


Run every command below from `ObserverRealTime/`.

`drip_hierarchy.h` exists in **two** places, `ObserverRealTime/` and the firmware folder, because the firmware compiles one and `check_hierarchy.py` reads the other. They must be kept identical but, ideally, there would be only one identity in the broadcast and the observer would use it to store it's trust anchors.

### 0.2 Serial ports and baud rates

| Board | Default port | Baud | Written by |
|---|---|---|---|
| Sniffer ESP32 (`DRIP_Sniffer.ino`) | `COM4` | **921600** | `SNIFFER_BAUD` in the sketch. Commands `radio`, `radio wifi`, `radio bt` are typed at this rate|
| Transmitter ESP32 | `---` | **115200** | The user in the Arduino IDE |

Change the port with `--port`, the rate with `--baud`.

**Only one program may hold a serial port at a time.** In practice that means:

- `arduino_logger.py` and `run_live.py` both open the port. Never run both.
- The Arduino IDE Serial Monitor also holds the port. Close it first.
- `live_observer.py` does **not** touch the port. It reads the capture file
  while `arduino_logger.py` writes it.
- `observer.py`, `make_vectors.py`, `check_hierarchy.py`, `make_map.py` and
  `replay_test.py` never open a serial port.

### 0.3 Dependencies

Python 3.13 or later. `cryptography` is optional and makes signature checking about 1300 times faster; without it the pure-Python `ed25519.py` is used and the Observer says so at startup. `dnspython` is needed only for the registry commands. `pyserial` is needed only for the two capture commands.

```bash
pip install cryptography dnspython pyserial
```

---

## 1. The transmitter

Source: `DRIP_Fleet_Broadcast/DRIP_Broadcast_RID/`. Open `DRIP_Broadcast_RID.ino` in the Arduino IDE | Board: **ESP32 Dev Module**.

**Partition scheme (required):** Tools > Partition Scheme > **Huge APP (3MB No OTA/1MB SPIFFS)**. The image carries both the Wi-Fi driver and the Bluedroid Bluetooth stack, 1.79 MB, and does not fit the default 1.31 MB app partition. With the default scheme the build stops with `text section exceeds available space in board`.

The board always boots on **Wi-Fi**. Bluetooth is selected at runtime with `radio bt`.

**Set the clock after every boot, before any capture: `time <unix>`.** Until then the board signs with 2026-01-01, and an Observer using real time reports every endorsement as expired (`E-LINK-04`).

Commands are typed into the Serial Monitor at **115200 baud**, or sent by `arduino_logger.py` without resetting the board. Matching is case-insensitive.

### 1.1 Fleet commands

| Typed | Effect | Prints |
|---|---|---|
| `time` / `time <unix>` | show / set the board's clock | `[Time] ...` |
| `identity` / `identity <0..5>` | show / change the focused slot's identity (Section 1.9) | `[Identity] ...` |
| `fleet` or `fleet list` | show the fleet | one row per slot: slot, address on the active radio, DET, flight, A/B/C phase, point, then a summary line and the active radio |
| `fleet <n>` | run `n` drones, 1 to 3, slot `i` flying flight `i`. While Bluetooth is active, `n` is limited to `DRIP_BLE_FLEET_MAX` (1) | re-signs the endorsement chain, then the fleet table |
| `fleet <n> same <flight>` | run `n` drones all replaying one flight | as above |
| `fleet set <slot> <flight>` | assign one slot's flight | as above |
| `focus <slot>` | choose which slot the single-drone commands below act on | confirmation |
| `debug off` | stop dumping packs | `[Fleet] pack dump off` |
| `debug on` | dump the focused slot's packs | the hex dump, once per cycle |
| `debug <slot>` | dump exactly that slot | as above |

### 1.2 Single-drone commands

These act on the **focused** slot, which is 0 until `focus` changes it. With `fleet 1` the console behaves exactly as the original single-drone build did.

| Typed | Effect | Prints |
|---|---|---|
| `<number>` | select that flight index for the focused slot and start it | the new flight, or `invalid index N (0..max)` |
| `list` | list the compiled flight tracks, then the fleet table | index, name and point count per flight |
| `info` | state of the focused drone | flight, name, point `i/n`, and `[finished — holding]` or `[stopped by command]` |
| `next` | advance one point by hand | lat, lon, alt, speed, heading and timestamp |
| `stop` | take the focused drone off the air | confirmation |
| `reset` | restart the focused drone at point 0 | `[Playback] drone N restarted at point 0` |


### 1.3 Radio: Wi-Fi or Bluetooth Legacy

Only one radio transmits at a time. The fleet, the identities and the Manifest hash chains are kept across a switch.

| Typed | Effect | Prints |
|---|---|---|
| `radio` or `radio status` | show the active transport; on Bluetooth also the counters below | `[Radio] active: ...` and, on Bluetooth, the lines listed below |
| `radio wifi` | ASTM F3411-22a §5.4.9 Wi-Fi Beacon, one Message Pack per beacon.| `[TX] Wi-Fi resumed ...`, `[Radio] active transport: Wi-Fi Beacon ...` |
| `radio bt` | ASTM F3411-22a §5.4.6 Bluetooth Legacy, one 25-octet message per advertisement. Refused while the fleet has more than `DRIP_BLE_FLEET_MAX` (1) drone: run `fleet 1` first | the first time, one `[BLE]` line per start-up step with its result, then `[BLE] ready ...`, `[TX] Wi-Fi suspended ...`, `[Radio] active transport: Bluetooth Legacy ...` |
| `radio slot <ms>` | set the Bluetooth slot, 5 to 1000 ms, without reflashing. Takes effect at the next message | `[Radio] BT slot = N ms (M messages/s)`, plus a WARNING when the slot is below interval + 10 ms |
| `radio int <units>` | set the advertising interval, `0x20` to `0x4000` (decimal or `0x` hex), units of 0.625 ms. Advertising restarts with it at the next message | `[Radio] BT advertising interval = 0x.. (.. ms)` |

**What Bluetooth sends each second, per drone** (RFC 9575 §6.4):

```
Basic ID, Location, System, Self ID, Operator ID, Manifest (about 9 pages, FEC), Basic ID, Location, System, one page of the Link (8 pages, FEC, one per second)
```

**`radio status` on Bluetooth, and the values that mean it is working:**

| Line | Healthy |
|---|---|
| `BT puts=` | grows by about 18 per second |
| `address switches=` | stays still with 1 drone |
| `put errors=`, `GAP errors=` | 0 |
| `overruns(>1 s + 1 slot)=` | 0 |
| `slot N: last period=` | 1000 ms to 1000 + one slot, for every slot |
| `cnt basic/loc/sys` | each grows by about 2 per second |
| `cnt self/oper` | each grows by about 1 per second |
| `cnt auth` | grows by about 1 per second, plus 1 every 8 s |

`debug on` prints one `[BT]` line per advertisement with its time, counter and message type or page number. `debug off` stops it.

**If `radio bt` fails**, the board stays on Wi-Fi and the failing step is named in the `[BLE]` lines. A failed Bluetooth start is not retried until the board is reset.

**Checking the air with a phone.** nRF Connect should show address `C2:44:52:49:50:00` with advertising data starting `1E 16 FA FF 0D`, changing several times per second. An app like Open Drone ID should show the drone's position moving along the track but don't check DRIP.


### 1.4 The clock: `time`

The board has no real clock. It boots with the build date (`SIM_DRIP_TIME_BASE`, 2026-01-01) and keeps it until told otherwise. Type in its Serial Monitor (115200):

| Typed | Effect | Prints |
|---|---|---|
| `time` | show the clock | `[Time] unix=... 2026-09-30T23:31:00Z DRIP=... (set by the 'time' command)` or `(NOT set - build default...)` |
| `time <unix>` | set the clock, then re-sign the endorsement chain (and rebuild the Link pages on Bluetooth) | the new time, then `[Time] endorsement chain re-signed ...` |

`<unix>` is a **Unix timestamp**: whole seconds since 1970-01-01 00:00:00 UTC,
digits only, for example `time 1790800260`. It is UTC by definition: do not
adjust it for the local time zone. Values before 2024-01-01 are rejected. Get
the current value on the PC:

| Where | Command |
|---|---|
| PowerShell | `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` |
| Python | `python -c "import time; print(int(time.time()))"` |
| Linux / macOS | `date +%s` |

A few seconds of typing delay do not matter; endorsements are valid for 24 h. **Order matters:** reset the broadcaster, set the time, choose the identity, and **only then** start the capture and the live Observer. The live view judges, for each (child, parent) pair, only the **newest** endorsement, so a January endorsement stops counting once the board has re-signed it after `time`. The batch report still lists every endorsement in the capture, expired ones included, because it is a record of what was broadcast. 
Switching identity counts as a **drone reboot** (author decision): the new identity starts a new Manifest chain, so switching **back** to an identity gives one `E-MAN-04`, which is expected. Endorsements sent before `time` keep the old date, and the Observer correctly reports them as `E-LINK-04`. A reset returns the board to 2026-01-01.

### 1.5 Identities: `identity` and every key of the bench

**Test values only.** Every key below is a published bench value. They are compiled into the firmware and written in the source, and the MOCK_DET_DRIP fork is public, so anyone can sign as any of these entities. None is registered anywhere real (RFC 9374 §3.3). Read "Safety" at the end of this section.

**Choosing the identity a drone broadcasts.** Each radio slot broadcasts one identity. The default is slot *i* = identity *i*. In the broadcaster's Serial Monitor (115200):

| Typed | Effect |
|---|---|
| `identity` | shows the focused slot's identity and lists all six |
| `identity <0..5>` | the **focused** slot (slot 0 with one drone; see `focus`) broadcasts that identity from now on |

- **Refusal:** the command is refused if another slot already broadcasts that
  identity, because two slots with one DET would look like an impersonation.
- **A new identity means a new UA:** the slot is provisioned again (new
  Manifest ledger, new counters) on the same flight, and the endorsement chain
  is re-signed. On Bluetooth the Link pages are rebuilt.
- **Where to see it:** `fleet` and `info` show the identity in use.
- **The choice is kept** across `fleet <n>` resizes, until the next reset.
- **Order:** set the clock before choosing an identity, as
  usual.

**The six UA identities:**
- **0, 1, 2:** valid, under chain A, listed in `hierarchy.json`.
- **3: malformed DET.** The broadcast DET is the correct one with its **last
  bit flipped**, so its hash no longer derives from its key (RFC 9374 §3.5.2).
  - Correct DET: `2001:30:3ff8:405:b113:9c81:d46a:cb84`.
  - The boot check prints an **error** if the fault ever disappears.
- **4: chain C.** A new RAA (15360, the RFC 9886 private-use / testing range)
  and HDA (100). **None of chain C is in `hierarchy.json`**, so the Observer must
  learn RAA C, HDA C and UA 4 from the air, anchored only by the Apex.
- **5: bad endorsement.** A valid DET under chain A, but one bit of its HDA→UA
  endorsement signature is flipped after signing (RFC 9575 §4.2).

Identities 3, 4 and 5 are deliberately **not** in `hierarchy.json`:
- for 3, the Observer would refuse the entry anyway, since its key does not
  derive its DET;
- for 4, absence is the point;
- for 5, a listed key would make the observer assign "Conflicting" for the drone since the trust exist but the endorsement is broken.

`check_hierarchy.py` now has a section 5 that **fails** if chain C ever appears
in the trust file.

**What the Observer reports.** Checked on endorsements produced by the
firmware's own code (see `PROGRESS.md`):

| Identity | Default anchor | Apex-only anchor | Live map |
|---|---|---|---|
| 0, 1, 2 | no findings | no findings, keys learned from the air | blue after confirming (green with Apex-only) |
| 3 | `E-LINK-01`, `E-KEY-01` | same | red |
| 3 with `--pubkey <identity 3 public key>` | `E-LINK-01`, **`E-DET-02`** | - | - |
| 4 | no findings, key learned from the air | same | green after confirming, **never blue** |
| 5 | `E-LINK-02`, `E-KEY-01` | same | red |

`E-DET-02` needs the Observer to **hold** the key. The Observer refuses to load
a key that does not derive its DET, which protects against a bad trust file. So
identity 3 shows as `E-LINK-01` (its endorsement binds a DET to a key that does
not produce it). `E-DET-02` appears only when you hand the key in as a
wildcard.

**Every entity of the bench:**

| Entity | DET | RAA/HDA | Where it is known | Expected Observer result |
|---|---|---|---|---|
| Apex | `2001:30:0:5:70f9:e8e9:b564:f448` | 0/0 | `hierarchy.json` (trust anchor) | root of every chain |
| RAA, chain A | `2001:30:3fc0:5:9024:e82a:8fd0:afb8` | 255/0 | `hierarchy.json` | endorsed by the Apex |
| HDA, chain A | `2001:30:3ff8:405:d162:233e:9b7e:feee` | 255/14340 | `hierarchy.json` | endorses UAs 0, 1, 2, 3, 5 |
| RAA, chain B | `2001:30:fa00:5:d18f:f62a:f870:d730` | 1000/0 | `hierarchy.json` | registry-only chain, not broadcast |
| HDA, chain B | `2001:30:fa07:d005:f0d2:b5a:871b:a28` | 1000/2000 | `hierarchy.json` | registry-only chain, not broadcast |
| RAA, chain C | `2001:3f:0:5:80a:9f96:d49f:7057` | 15360/0 | **not** in `hierarchy.json` (air-only) | endorsed by the Apex |
| HDA, chain C | `2001:3f:0:6405:f18a:e883:952e:9b04` | 15360/100 | **not** in `hierarchy.json` (air-only) | endorses UA 4 |
| UA identity 0 | `2001:30:3ff8:405:d952:5618:fbc9:c3cf` | 255/14340 | `hierarchy.json` | valid; no findings |
| UA identity 1 | `2001:30:3ff8:405:8412:4323:5d3c:a050` | 255/14340 | `hierarchy.json` | valid; no findings |
| UA identity 2 | `2001:30:3ff8:405:a57e:87ab:5388:cbb8` | 255/14340 | `hierarchy.json` | valid; no findings |
| UA identity 3 | `2001:30:3ff8:405:b113:9c81:d46a:cb85` | 255/14340 | **not** in `hierarchy.json` | MALFORMED DET: `E-LINK-01` + `E-KEY-01`; `E-DET-02` only with `--pubkey` |
| UA identity 4 | `2001:3f:0:6405:b6ae:eea3:d5b:898c` | 15360/100 | **not** in `hierarchy.json` | valid, chain C: no findings; key learned from the air; map green at most |
| UA identity 5 | `2001:30:3ff8:405:a5c7:51d1:7b8c:6526` | 255/14340 | **not** in `hierarchy.json` | BAD ENDORSEMENT: `E-LINK-02` + `E-KEY-01`; map red |

Keys (Ed25519, RFC 8032: the private key is the 32-octet seed; the public key is the Host Identity):

**Apex**
```
DET          2001:30:0:5:70f9:e8e9:b564:f448
private seed A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF
public key   4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4
```
**RAA, chain A**
```
DET          2001:30:3fc0:5:9024:e82a:8fd0:afb8
private seed C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF
public key   DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8
```
**HDA, chain A**
```
DET          2001:30:3ff8:405:d162:233e:9b7e:feee
private seed E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
public key   13D9908A70925992ED546007D27F50DA68BA7217EF62AC3CCA784529FF10471C
```
**RAA, chain B**
```
DET          2001:30:fa00:5:d18f:f62a:f870:d730
private seed 404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
public key   2543B92FF1095511476ADC8369DB6DDC933665A11978DDA1404EE1066CA9559D
```
**HDA, chain B**
```
DET          2001:30:fa07:d005:f0d2:b5a:871b:a28
private seed 606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
public key   174553B456DDDFC6908ECAB1C101FE6AB21E2BAA0617795B7D43A63482993FD5
```
**RAA, chain C**
```
DET          2001:3f:0:5:80a:9f96:d49f:7057
private seed 808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F
public key   CD14B37F956E953194FF7FB73B3D81DCC561D61A7538094B7C3E1A643EE5F3AA
```
**HDA, chain C**
```
DET          2001:3f:0:6405:f18a:e883:952e:9b04
private seed 202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
public key   29ACBAE141BCCAF0B22E1A94D34D0BC7361E526D0BFE12C89794BC9322966DD7
```
**UA identity 0**
```
DET          2001:30:3ff8:405:d952:5618:fbc9:c3cf
private seed 59129C5C9AB2C7F188010432002361D513F265248D9E0BF0A0770AD2ED677817
public key   F505704EB544F861190F2D8EDAC9BA83F320D5E38726B3F51C220851320EC7E6
```
**UA identity 1**
```
DET          2001:30:3ff8:405:8412:4323:5d3c:a050
private seed F5D22D330869D9060A972964191BEBA9F6CCA4BD3610E87619E4782D164A5666
public key   F7D792E5DD000E8C05DCEEB357D03AF1770B0D7D6BFE429AABBD3C3F1CB16FE2
```
**UA identity 2**
```
DET          2001:30:3ff8:405:a57e:87ab:5388:cbb8
private seed 6CFFCF5B80CF70E585346EB47E9A8B41CA884CBA8B1DBE45626D1CBCD5CD7C77
public key   B80BC263962420FBF1454E61BB149FCD1BDC447195B12D63C69E7FB7AEAAC3AC
```
**UA identity 3**
```
DET          2001:30:3ff8:405:b113:9c81:d46a:cb85
private seed 024DCBE9E4F835F6F17240DDE1647057F19A91191D29E77F75D5224CE6CB8405
public key   9A77BAAA906F8F048C61BC06EF4094AD4DF7634462CBF3B2484734E7FFC0644B
```
**UA identity 4**
```
DET          2001:3f:0:6405:b6ae:eea3:d5b:898c
private seed 73DBF2DC4FFA90432A9A2FCEB4B43828604680FA1A607B55885DA672BA21A2DC
public key   A183B4B8E3FFA24168841542FE69CA994B0D7C1F0B5E9F8E6D814FF1FA5C09F5
```
**UA identity 5**
```
DET          2001:30:3ff8:405:a5c7:51d1:7b8c:6526
private seed C31AAF7858F71F1277B630A1E5EFF29535E8EF18A461DC85D8D5AB0414CAD8B1
public key   A6278B299968FEE58BBD7F57571C2118D0D3245D302CDB07F2C6735807958B8F
```

**Not in the table:** `hierarchy.json` also lists
`2001:30:3ff8:405:5c76:7822:e2ed:15bc`. It is the DET registered in the
collaborating researcher's registry. The bench holds no key for it, so it is
only checked against DNS.

**Reproducing these values.** Run the following in the Observer folder, with
`det.py` and `ed25519.py`:
- UA identity 0 uses the seed above (supplied externally, with permission);
- UA identities 1 to 5 use `det.shake128(b"DRIP PoC UA slot <i>", 32)`;
- the authorities use the byte patterns in `drip_hierarchy.h`;
- each DET is `det.compute_det(public_key, RAA, HDA, 5)`;
- identity 3 then has its last bit flipped.

**Safety (what this bench must never be confused with):**
1. **Every private key here is public.** Signatures from these identities prove
   nothing to anyone outside the bench. Never register these DETs or keys in a
   real registry, and never reuse them on a real aircraft.
2. **The broadcaster holds the Apex, RAA and HDA private keys** (`DRIP_TEST_BE`),
   so it can sign its own endorsements. In a real system a UA holds **only its
   own** key; the endorsements come from the registry. This is the largest
   difference from a real deployment, and the reason `DRIP_TEST_BE` must never
   be compiled into a flight image (it prints a warning at boot).
3. **Keys sit in plain flash.** A real UA keeps its key in protected storage,
   for example with ESP32 flash encryption, and ideally generates it on the
   device.
4. **The RAA/HDA numbers are not IANA-assigned.** Chains A and B use numbers
   from assignable ranges; only chain C uses the private-use range. A real
   deployment needs assigned numbers (RFC 9374 §3.3).
5. **Identities 3 and 5 are faulty on purpose.** Their findings are the
   expected result, not a defect.
6. **Identity 0's key comes from another research bench,** used with that
   researcher's permission.

---

## 2. Capturing the air

The sniffer boots on Wi-Fi (Format A, unchanged). `radio bt` switches it to
Bluetooth Legacy (Format BT).

### 2.1 Capture to a file

```bash
python arduino_logger.py --port COM3 --baud 921600 -o capture.txt
```

Prints `Connected without resetting the board`, then one progress line per
second giving the lines and bytes written. Ctrl+C stops it.

| Flag | Default | What it changes |
|---|---|---|
| `--port PORT` | `COM4` | the serial port |
| `--baud N` | 921600 | the serial rate; use 115200 for the transmitter log |
| `-o FILE` | `data_log.txt` | the output file |
| `--select N` | none | send flight index `N` after connecting |
| `--cmd TEXT` | none | send any console command after connecting |
| `--echo` | off | print every line to the console |

**`-o` truncates.** Running twice with the same name destroys the earlier
capture. Prefer `run_live.py`, which timestamps the filename by default, or pass
a fresh name each session.

**Do not use `--echo` at 921600.** Rendering every line stalls the reader, the
operating system serial buffer overflows, and bytes are discarded silently. The
Observer will report those frames as `W-CAP-01`.

### 2.2 Capture and watch at the same time

```bash
python run_live.py --port COM3
```

Starts the capture and the live map together and opens a browser at
`http://127.0.0.1:8080`. Ctrl+C stops both. The capture is written to
`capture_YYYY-MM-DD_HHMM.txt` unless `-o` says otherwise.

### 2.3 Watch a capture another window is writing

```bash
python live_observer.py capture.txt
```

Does not touch the serial port. Starts at the end of the file and shows what
arrives from now on.

Flags shared by `run_live.py` and `live_observer.py`:

| Flag | Default | What it changes |
|---|---|---|
| `--anchor FILE` | `hierarchy.json` | the trusted-identities file |
| `--keyring FILE` | none | extra `DET_HEX PUBKEY_HEX` pairs, one per line |
| `--pubkey HEX` | none | a wildcard key for any DET with no entry |
| `--no-builtin-keys` | off | do not load the trust file at all |
| `--host ADDR` | `127.0.0.1` | the address the page is served on |
| `--web-port N` | 8080 | the page port |
| `--stale SEC` | 10 | silence before an aircraft is marked stale |
| `--drop SEC` | 90 | silence before an aircraft leaves the map |
| `--grace SEC` | 4 | delay before a Manifest cross-check is judged |
| `--warmup SEC` | 4 | initial period whose Manifest misses are not reported |
| `--trail N` | 500 | points kept per aircraft |
| `--now UNIX` | none | reference time for the freshness check |
| `--max-age SEC` | none | tolerance for that check |
| `--from-start` | off | replay the whole file rather than starting at its end |
| `--no-browser` | off | do not open a browser |

`--host` is loopback by default because the page carries aircraft positions and identities. Change it deliberately or not at all.

**The live view is a monitoring aid.** The authoritative result is a batch run over the finished capture, which is Section 3.

### 2.4 Sniffer radio commands

Flash `DRIP_Sniffer.ino` with Tools > Partition Scheme > **Huge APP (3MB No OTA/1MB SPIFFS)**; with the default scheme it is 113% of the app partition.

Typed at **921600** baud, or sent with `arduino_logger.py --cmd`. Every reply is a `#` comment line, which every capture parser ignores.

| Typed | Effect |
|---|---|
| `radio` or `radio status` | `# radio=wifi\|bt captured=.. dropped=.. oversize=.. bt_non_odid=..` |
| `radio wifi` | channel 6 promiscuous Beacon capture, Format A, byte-identical to before |
| `radio bt` | Bluetooth passive scan, 100% duty (interval = window = 50 ms), duplicate filter off. The first time, one `# BT` line per start-up step. On failure it stays on Wi-Fi |

Format BT, one advert per two lines:

```
#B addr=C2:44:52:49:50:00 rssi=-42 t_ms=12345 len=29 t_us=12345678 atype=1
FA FF 0D 07 02 12 ...
```

The hex is the Service Data from the UUID on: `FA FF`, App Code `0D`, the
counter, one 25-octet ASTM message. `t_us` is the sniffer's own clock, not wall
time. The first four fields match the MOCK_DET_DRIP fork's Format BT; `t_us`
and `atype` are appended after `len`. The periodic `# stats` line now ends with
`radio=wifi` or `radio=bt`.

### 2.5 Reading the live map colours (RFC 9575 Appendix A)

Each drone's **marker** shows its authentication state. Its **track** keeps
the drone's identity colour (cyan, magenta, light pink; dashed from the 4th
drone), which is never a state colour. The legend is at the bottom left of the
map.

| Marker | State | Meaning on this bench |
|---|---|---|
| black | None | no Authentication received yet |
| gray | Partial | Authentication pages seen, no complete message |
| brown | Unsupported | only Authentication types this Observer cannot verify |
| yellow | Unverifiable | waiting for a key or chain, **or** all checks verified but "Confirmed by observation" not pressed |
| green | Verified | all checks verified and confirmed; key not under trusted registrars only |
| blue | Trusted | as green, and the key is in the trust file or reached the Apex only through RAAs/HDAs of the trust file |
| red | Unverified | only failed checks |
| orange | Questionable | both verified and failed checks |
| purple | Conflicting | both, with a trusted key |

The colour is judged on the drone's **last complete endorsement cycle**, the period in which every link of its chain (UA ← HDA ← RAA ← Apex) was received once, plus the cycle in progress. That is about 18 s on Wi-Fi and about 48 s on Bluetooth. Until two cycles have completed, the whole session counts. The panel shows: - 

**CURRENT CYCLE:** findings inside the window; they drive the colour; - 

**EARLIER - no longer affecting the state:** greyed, with full counts and   times. Nothing is hidden.

The reason line names the window, for example "started 16 s ago (10 cycles so far)". This is a deliberate departure from RFC 9575 Appendix A's cumulative wording (author decision, 2026-10-04): a transient failure leaves the colour after one clean cycle. The batch report still counts everything. 

**"Confirmed by observation"** is in each drone's panel. Press it only after correlating the drone with another source, for example seeing it where the map shows it (RFC 9575 §6.4.2). Press again to withdraw. It lasts until the observer stops, is echoed on the terminal, and changes no finding.

Notes:
- With an Apex-only anchor no drone can be blue or purple: its RAA and HDA come   from the air, not from the file.
- With the broadcaster on its default January clock (no `time` command), the   expired endorsements make the drone purple (default anchor) or red (Apex-only   anchor).

---

## 3. Decoding and validating a capture

### 3.1 The ordinary run

```bash
python observer.py capture.txt
```

The Observer detects the format by itself and refuses the file rather than guessing when nothing matches. Five formats are recognised: Format A (the sniffer's Wi-Fi air capture), Format BT (the sniffer's Bluetooth capture, also mixed with A; reported as `BT` or `A+BT`), Format L (the transmitter's serial log), Format W (a Wireshark bytes export) and Format B (flat hex).

**Reading a Bluetooth capture.** Each advertisement is one message, so pages of a Manifest or Link are regrouped by sender address and Message Counter, and one lost page is rebuilt with FEC (RFC 9575 §5). The report adds a **Bluetooth Legacy capture health** block. Its counts are **not findings**: they describe the radio path.

| Line | Meaning |
|---|---|
| `Authentication messages N: complete / rebuilt by FEC / lost / page 0 never received` | "lost" = 2 or more pages missing; such a message is not judged at all |
| `Manifest hash(es) of messages not received` | RFC 9575 §4.4 lets an Observer verify only what it received; on Wi-Fi the same case is `E-MAN-02` |
| `Manifest chain gap(s)` | a Manifest was lost, so the next one was not chain-compared (`E-MAN-04` only between consecutive Manifests, under 1.6 s apart) |

**Wi-Fi uses the same rule** when the capture has receive times (Format A, and the live view). `E-MAN-04` is raised only between Manifests under 4.5 s apart (the bench sends one every 3 s); a larger gap means a Manifest beacon was lost, and it is counted, not reported. Switching back to an identity after a pause therefore also shows as a chain gap. Formats W, B and L have no receive time and keep the strict check.

| `Manifest(s) whose Link could not be checked` | no Link arrived at all, or the capture ended less than 60 s after the Manifest. RFC 9575 §6.3 only requires the HDA→UA Link once per minute, so a shorter wait cannot tell "late" from "missing". The live view also waits 60 s on Bluetooth before `E-MAN-03` (Wi-Fi: `--grace`, 4 s) |

Codes that exist only because of Bluetooth: `E-FEC-01` (ADL or padding wrong), `E-FEC-02` (parity page wrong), `E-FEC-03` (Legacy Authentication without FEC), `E-FEC-04` (FEC inside a Wi-Fi pack). `E-SEM-01` on Bluetooth means an address sent DRIP Authentication but no DRIP Basic ID anywhere in the capture.

It prints, in order: the trust anchor in use, the Ed25519 backend and its self-test, the detected format, a message-type histogram, capture health, the identity table with the provenance of each key, the key-provenance summary, the findings grouped by identity, and the findings grouped by code. Exit status is 0 when there are no findings and 1 when there are any.

| Flag | Default | What it changes |
|---|---|---|
| `--anchor FILE` | `hierarchy.json` | the trusted-identities file, which supplies the Apex and every pre-loaded identity |
| `--keyring FILE` | none | additional `DET_HEX PUBKEY_HEX` pairs, one per line, `#` comments allowed |
| `--pubkey HEX` | none | a 64-character hex key applied to any DET with no entry of its own |
| `--no-builtin-keys` | off | do not load `--anchor` at all, so only `--keyring` and `--pubkey` supply keys |
| `--list-keys` | off | print the keyring and exit; no capture file needed |
| `--now UNIX` | none | reference time, which enables the freshness and validity-window checks |
| `--max-age SEC` | none | tolerance for the freshness check; needs `--now` |
| `--pure-python` | off | force `ed25519.py` and ignore the accelerated backend |
| `--verbose` | off | print every decoded item and every finding rather than the first five per code |
| `--offer-trust` | off | after the run, ask per identity learned from the air whether to write it into `--anchor` |
| `--dns-fallback` | off | look up an unknown DET in DNS once per run; needs network and `dnspython` |
| `--dns-server IP` | `141.227.148.117` | the resolver for the DNS paths |

### 3.2 A run with no pre-loaded aircraft

This is the offline case the suite is designed around: the Observer holds the Apex and learns everything else from the air.

```bash
python observer.py capture.txt --anchor apex-only.json
```

Build `apex-only.json` by copying `hierarchy.json` and deleting the `raas`, `hdas` and `ua` arrays. The key-provenance summary should then read `1 from trust file, N from air`.

### 3.3 Checking freshness against a reference time

```bash
python observer.py capture.txt --now 1782000000 --max-age 60
```

`--now` is a **Unix** timestamp. The Observer converts it to the DRIP epoch itself for the validity-window check. Supplying it against the bench's simulated clock places every window in the past, which is a deliberate negative test.

### 3.4 Reading the keyring

```bash
python observer.py --list-keys
```

Prints every DET the trust file supplies, with its label and its public key. No capture file is needed.

---

## 4. Resolving an identifier

### 4.1 Offline, against the trust file

```bash
python observer.py --resolve 2001:30:3ff8:405:d952:5618:fbc9:c3cf
```

Accepts the colon form or 32 hex characters. Touches no network. Prints the decoded fields, the RAA and HDA zones, the reverse `ip6.arpa.` name, whether the identifier is on the allow-list and at which level, and whether its registered key derives it. Exit status is 0 when nothing was raised and 1 otherwise.

### 4.2 Against the registry

```bash
python observer.py --dns-lookup 2001:30:3ff8:405:5c76:7822:e2ed:15bc
```

Performs a reverse PTR query, then a TXT query on the name it returns, and verifies the DET-to-key binding on whatever key comes back. Needs network and `dnspython`. Offers to write the identity into `--anchor` only when the binding verified.

Use a different resolver with `--dns-server IP`.

### 4.3 Registry lookup while reading a capture

```bash
python observer.py capture.txt --dns-fallback
```

Each DET absent from the trust file is looked up **once** per run. On a verified binding the operator is offered three choices:

| Answer | Effect |
|---|---|
| `w` | write the identity into `--anchor` and use it for the rest of the run |
| `t` | use it for this run only; nothing is written |
| `n` | ignore the identity for the rest of the run |

Without a terminal the tool verifies with the key for this run and never writes. A binding that fails is reported and never offered for writing.

The same fallback resolves an Apex, RAA or HDA that the capture never carried, which is what allows a chain with a missing parent to be anchored from the registry. Any key obtained this way is recorded with provenance `registry`, and the report states that the run was network-dependent.

### 4.4 Persisting what a capture taught

```bash
python observer.py capture.txt --offer-trust
```

After the report, each identity whose key came from an endorsement is listed and the operator is asked whether to write it into `--anchor`. **There is no automatic write path for an air-learned key.** Without this flag such a key is valid for the run that learned it and nothing else.

---

## 5. Self-tests and the hierarchy

### 5.1 The reference encoder

```bash
python make_vectors.py --selftest
```

Runs five suites, 56 checks, and exits 0 only when all five pass:

| Suite | Cases | What it proves |
|---|---|---|
| structural | 22 | each deliberately broken ASTM or DRIP vector raises exactly its code, and each valid one raises none |
| DRIP Link chain | 5 | the endorsement walk accepts a good chain and names the right code for each broken one |
| DRIP Manifest | 6 | signature, self-hash, pack and link cross-checks, and the per-aircraft ledger |
| trust model | 5 | the five cases C1 to C5: unknown aircraft with an Apex-only trust file, Wrapper before Link, cyclic chain, unanchored Link, expired endorsement |
| Bluetooth Legacy / FEC, Link wait, Wi-Fi gaps (session 3) | 18 | a clean Format BT capture of the §6.4 schedule; one lost Manifest or Link page rebuilt by FEC; two lost pages counted, not judged; `E-FEC-01` to `E-FEC-04`; `E-SEM-01` and `E-MAN-04` on Bluetooth; a Manifest covering a message not received; a mixed Wi-Fi + Bluetooth capture |

Write the structural vectors to a file instead:

```bash
python make_vectors.py --write vectors.txt
```

Then read them back like any capture: `python observer.py vectors.txt`.

### 5.2 The hierarchy

```bash
python check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
```

Run this after editing either file. It proves four things and exits 1 on any
failure:

1. every DET in `hierarchy.json` re-derives from its own public key;
2. the numbers in the header and the JSON agree, and the header's private seeds
   produce the JSON's public keys;
3. the RAA and HDA numbers are well formed under RFC 9886 §6.2.1;
4. every authority listed derives, and no public key is held by more than one.

Check UA keys from a keyring file instead of the trust file with
`--ua-keys FILE`.

### 5.3 The identity module

```bash
python det.py
```

Runs the Keccak core against `hashlib`, reproduces the NIST cSHAKE128 sample, reproduces the RFC 9374 Appendix B.1 worked example, and round-trips the recorded identity. Then prints that identity in every representation.

### 5.4 Generating a new identity

```bash
python newkey.py
```

Prints a fresh seed, its public key and the DET it produces under the RAA and HDA compiled into the script. The seed is a private key; it is printed so it can be pasted into the firmware, and it must not be committed anywhere public.

### 5.5 Replaying a capture through the live path

```bash
python replay_test.py capture.txt
```

Feeds a finished capture into the live path at the speed of its own timeline and prints what the live observer concluded. Used to check that the live and batch paths agree. Not part of the deliverable.

---

## 6. Plotting a capture

```bash
python make_map.py capture.txt -o map.html
```

Writes one self-contained HTML file plotting each aircraft's path, coloured per identifier, with a green marker at the first point and a red one at the last. Open it by double-clicking. The browser fetches the map library and the tiles from public services, so viewing needs internet access even though producing the file does not.

`--title TEXT` sets the page heading.

---

## 7. The regression gate

Run all of this after any change to the Observer or the reference encoder, and compare against the reports from before the change:

```bash
python make_vectors.py --selftest
```

```bash
python check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
```

```bash
python observer.py capture_2026-07-23_1112.txt
```

Repeat the last line for every stored capture, Wi-Fi and Bluetooth. Session 3 changed the Wi-Fi path of the Observer in one place only (the `E-FEC-04` check on complete Authentication messages in a pack); every stored Wi-Fi capture must give the same report as before. A vector or a capture that passed before and fails after is a regression. A code whose count rises needs an explanation before it is accepted.

`data_log.txt` is not a capture. The Observer refuses it with `unrecognized input format` and exit status 2, which is correct.

---

## 8. Exit statuses

| Status | Meaning |
|---|---|
| 0 | no findings, or the requested action succeeded |
| 1 | findings were reported, or a self-test failed |
| 2 | the input could not be used: unknown format, missing file, bad argument |
