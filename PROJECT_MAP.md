# PROJECT_MAP.md

One entry per source file: what it is for, what it owns, what it depends on, and
the constraint a future editor has to respect. Operating instructions are in
`COMMANDS.md`.

This file was generated using IA and may contain errors.

Last updated 05/10/2026.

---

## 0. What is in this folder, and what is not

The bench has five subsystems, and all five have their sources here.

| Subsystem | Where |
|---|---|
| Firmware transmitter | `DRIP_Fleet_Broadcast/DRIP_Broadcast_RID/` |
| Firmware sniffer | `ObserverRealTime/DRIP_Sniffer/DRIP_Sniffer.ino` |
| Observer | `ObserverRealTime/observer.py` and its modules |
| Analysis tooling | `ObserverRealTime/make_vectors.py`, `check_hierarchy.py`, `make_map.py`, `newkey.py` |
| Test vectors and captures | `ObserverRealTime/capture*.txt`, and whatever `make_vectors.py --write` produces |

### 0.1 Copies of the same file

| Folder | Contents | Status |
|---|---|---|
| `ObserverRealTime/` | Observer, tooling, sniffer sketch, live path | **the working copy** |
| `ObserverRealTime/files/` | a copy of the live-path files | a distribution bundle; do not edit |

`drip_hierarchy.h` exists twice, once in `ObserverRealTime/` and once in the
firmware folder, because the firmware compiles one and `check_hierarchy.py`
reads the other. A change to either must be copied to the other.
`check_hierarchy.py` is what catches a divergence, and it can be pointed at
whichever copy is in doubt with `--header`.

---

## 1. Data flow, transmitter to verdict

```
  transmitter ESP32
      builds a Message Pack per aircraft, once per second, rotating three
      compositions: Wrapper pages, Link pages, Manifest pages
          |
          |  802.11 beacon frame, channel 6, vendor IE221 OUI FA-0B-BC type 0x0D
          v
  sniffer ESP32  (DRIP_Sniffer.ino)
      promiscuous on channel 6, keeps beacons carrying that IE, prints each as
      hex with an RSSI and byte-count header line
          |
          |  USB serial, 921600 baud
          v
  arduino_logger.py         writes the bytes to a capture file (Format A)
          |
          +---------------------------> live_feed.py -> live_state.py -> live_server.py
          |                              (the live map; a monitoring aid)
          v
  observer.py
      1. odid.py           parses frames, packs, messages, auth pages; no judgement
      2. validate_*()      structural, pack and auth-paging codes
      3. deferred queue    evidence whose key is not yet known is put aside
      4. verify_link_chain anchored walk: descends from the trusted identities,
                           admits an endorsement only when its parent is trusted,
                           and teaches the keyring each key it admits
      5. verify_manifests  ledger, hashes, cross-checks
      6. drain             the queued evidence is judged with the keys now held
          |
          v
  report: identities, the provenance of each key, findings by identity and by code
```

**Bluetooth Legacy path (session 3).** `radio bt` on both boards swaps the
middle of the diagram:

```
  transmitter: ONE 25-octet message per advertisement (ADV_NONCONN_IND, static
      random address C2:44:52:49:50:0N), RFC 9575 §6.4 schedule, 18 per second
          |  BLE channels 37/38/39, Service Data UUID 0xFFFA, App Code 0x0D
          v
  sniffer: passive 100 % scan, every copy -> '#B addr=.. t_us=..' + hex (Format BT)
          v
  observer.py: odid.LegacyAssembler groups pages by (address, counter), rebuilds
      one lost page with FEC; lost messages are COUNTED, never judged; then the
      same steps 4-6 as above. bt_timing.py measures the timing of the same file.
```

A capture can mix both formats (the sniffer switched radios); segments are
processed in file order.

The one ordering constraint that matters: the chain walk runs **after** the
whole capture has been decoded and **before** the evidence is judged. Verifying
evidence during the decode made the verdict depend on the order in which frames
arrived, which RFC 9575 §6.4.2 does not permit.

---

## 2. Firmware transmitter

`DRIP_Fleet_Broadcast/DRIP_Broadcast_RID/`. Arduino sketch, ESP32 Dev Module.

### `DRIP_Broadcast_RID.ino`
**Purpose.** Setup and loop. Brings up the radio through `rid_transport_init()`
(Wi-Fi, as before), initialises the fleet, and polls the console.
**Build (session 3).** Tools > Partition Scheme > "Huge APP (3MB No OTA/1MB
SPIFFS)": Wi-Fi plus Bluedroid is 1.79 MB, 136 % of the default partition.
**Owns.** The 115200 baud console rate.
**Constraints.** Build switches do not belong here. In the Arduino model each
`.cpp` compiles separately, so a `#define` in the sketch reaches only the
sketch. They live in `drip_config.h`.

### `drip_config.h`
**Purpose.** Every project-wide build switch, in one place every unit includes.
**Owns.** `DRIP_TEST_BE`, `DRIP_TEST_IMPERSONATION`, `DRIP_IMPERSONATOR_SLOT`,
`DRIP_IMPERSONATED_SLOT`. Session 3: `DRIP_BLE_ADV_SLOT_MS` (30),
`DRIP_BLE_ADV_INT_UNITS` (0x20), `DRIP_BLE_FLEET_MAX` (1), and the fabricated
`DRIP_TEST_SELF_ID_*` / `DRIP_TEST_OPERATOR_ID*` values.
**Constraints.**
- `DRIP_TEST_BE` fabricates the whole Apex, RAA and HDA chain. A production
  image must not define it.
- `DRIP_TEST_IMPERSONATION` builds an aircraft that lies about its identity. It
  is a **compile-time** switch on purpose: a console command that turns an
  aircraft into an impersonator would be a weapon left in the field. Two
  `#error` guards enforce that the two slots differ and that `DRIP_TEST_BE` is
  present, since the experiment retransmits the victim's endorsement.
- An adversarial build announces itself at boot, because nothing on the air
  distinguishes it. Looking exactly like the victim is the point.
- **(session 3)** The two BLE timing values are bench parameters, not standard
  values, and are only the boot defaults of `radio slot` / `radio int`. Self ID
  and Operator ID are test values; the Observer's `make_vectors.py` uses the
  same ones, and no CAA issued them.

### `drip_time.h`
**Purpose.** `drip_timestamp()`, the only clock in the firmware. **(session 3)**
Its base is a variable, set at runtime by `time <unix>` (`drip_time_set_unix()`,
called from `drone_fleet.cpp`); `SIM_DRIP_TIME_BASE` is now only the boot value.
A clock change must be followed by re-signing the endorsement chain, which the
`time` command does.
**Constraints.** Every timestamp the board emits derives from it: the DRIP VNB
and VNA, the Authentication header, the ASTM System message, and the ASTM
Location message. Keeping one source is what makes those four agree, which is
what 14 CFR §89.310(b) requires of the time mark. Adding a second time source
would reintroduce the divergence this bench had.

### `f3411_messages.cpp` / `.h`
**Purpose.** Builds the ASTM F3411-22a Basic ID, Location and System messages,
and **(session 3)** Self ID (Table 10) and Operator ID (Table 12), sent on
Bluetooth only.
**Owns.** `DRIP_EPOCH_UNIX_S` (1546300800, fixed by the standard),
`SIM_DRIP_TIME_BASE` (**configuration**, currently 220924800 = 2026-01-01),
`DRIP_VNA_OFFSET_S` (120), and the SAM type constants.
**Constraints.** `SIM_DRIP_TIME_BASE` is the board's entire notion of the date.
A value in the past makes every window the firmware signs expire before an
Observer using real time sees it, which is why a live run against a stored
capture reports `E-LINK-04` on every endorsement. Update it before a session
whose timing matters.

### `det_generator.cpp` / `.h`
**Purpose.** DET construction, the identity slot table, and signing.
**Owns.** `IDENTITY_TABLE`, three slots of seed, public key and expected DET;
`DET_IDENTITY_SLOTS` (3); `det_compute()`; `det_load_identity()`;
`det_sign_with()`; `det_to_session_id()`.
**Depends on.** `cshake128.cpp`, `drip_hierarchy.h`, and the Arduino Crypto
library by Rhys Weatherley for Ed25519.
**Constraints.**
- Every slot self-checks at boot: the seed must derive the recorded public key,
  and that key must derive the recorded DET. A slot failing either is marked
  invalid and cannot sign, rather than signing with something wrong.
- The seeds are **private keys in plain flash**. Acceptable only because every
  key here is a published bench value with no registration behind it.
- Identity is bound to the **slot**, never to the flight, which is what lets two
  drones fly one recorded track under different identifiers.
- `hierarchy.json` on the Observer side must list the same three DETs and public
  keys. Nothing checks this automatically; the script recorded in `PROGRESS.md`
  re-derives all three from the table.

### `drip_hierarchy.h`
Described in Section 7, since it is shared with the Observer.

### `drip_registration.cpp` / `.h`
**Purpose.** Fabricates the Apex, RAA and HDA key pairs and signs the chain of
Broadcast Endorsements, one per aircraft at the leaf.
**Owns.** `DRIP_BE_VALIDITY_S` (86400), the per-slot Cycle-B rotation cursor,
and the six-position rotation pattern.
**Constraints.** Compiled only under `DRIP_TEST_BE`. The signatures are real
Ed25519 over `VNB || VNA || DET_child || HI_child || DET_parent`, which is what
makes the chain worth walking. Zero-filling was rejected deliberately: it would
validate the paging and nothing about the byte order fed to the signer.

### `drip_auth.cpp` / `.h`
**Purpose.** Builds the DRIP Wrapper (RFC 9575 §4.3.2, Extended Transport).
**Owns.** The 89-octet wire payload, the evidence ordering rule, and the
4-message evidence limit.
**Constraints.** Evidence is filled for signing and then **cleared** before
transmission, per §4.3.2, so the wire payload is a fixed 89 octets in 5 pages.
The receiver rebuilds the signed bytes from the pack itself, so the evidence
ordering rule here, a stable sort ascending by ASTM message type, must match
`odid.reconstruct_wrapper_evidence()` exactly.

### `drip_manifest.cpp` / `.h`
**Purpose.** Builds the DRIP Manifest and maintains the per-aircraft hash
ledger.
**Constraints.** Each aircraft owns its Prev/Curr chain (RFC 9575 §4.4.2),
seeded from the hardware RNG so two drones never share one. The Manifest
references `BE:HDA,UA` specifically, so it hashes that leaf regardless of which
endorsement actually went out in the current Cycle B.
**(session 3)** `drip_manifest_build_legacy()` hashes single 25-octet messages
(RFC 9575 §4.4.3.1), recorded by `drip_manifest_note_message()` only once they
are on the air, at most 10 (§4.4), and pages the result with FEC. The Current
hash is computed over the whole Evidence, Link hash included, on both
transports; RFC 9575 §4.4.3 step 4 does not name the Link hash (open question in
`PROGRESS.md`), and `observer.py` E-MAN-05 follows the firmware.

### `drip_link.cpp` / `.h`, `drip_auth_page.cpp` / `.h`
**Purpose.** Serialise a Broadcast Endorsement into a DRIP Link SAM, and
scatter any SAM payload across ASTM Authentication pages.
**Constraints.** A Link is 137 octets and therefore seven pages, which with the
mandatory Basic ID and Location fills a nine-slot pack exactly. That is why
Cycle B omits the System message.
**(session 3)** `drip_auth_scatter_fec()` adds RFC 9575 §5.1 Single Page FEC
(ADL, null padding, parity page; LPI includes it). It is for Legacy only: §6.2
forbids FEC in a Message Pack, so `drip_auth_scatter()` is unchanged.
`drip_link_build_be_fec()` gives the 8-page Link.

### `drone_fleet.cpp` / `.h`
**Purpose.** Owns the virtual aircraft, the A/B/C cycle, the console, and
transmission scheduling.
**Owns.** `FLEET_MAX` (3), `FLEET_PACK_PERIOD_MS` (1000),
`FLEET_BEACON_PERIOD_MS` (500), the per-slot `VirtualDrone` state, and the
command parser.
**Constraints.**
- Drones are phase-staggered across the pack period so at most one Ed25519
  signature is in flight at any instant.
- The pack hex dump auto-disables above one drone. At 115200 baud a single
  drone's dump already uses about 90 per cent of the link, so dumping more would
  block the scheduler inside `Serial.print()`.
- `fleet_broadcast_identity()` is the only place the broadcast identity can
  differ from the slot's own, and it exists only under
  `DRIP_TEST_IMPERSONATION`.
- **(session 3)** It reaches the radio only through `rid_transport`. The
  `radio [status|wifi|bt|slot|int]` command lives here. The Bluetooth scheduler
  sends the RFC 9575 §6.4 second (Basic ID, Location, System, Self ID, Operator
  ID, FEC Manifest, Basic ID, Location, System, one Link page), one message per
  slot, one Message Counter per type (ASTM §5.4.4.2), one counter per
  Authentication message shared by its pages (BUR0060). The Manifest sits
  between the two sets, not after them as RFC 9575 Figure 13 does, to keep the
  two Location messages about half a second apart (BUR0010). Several drones are
  sent as bursts, but `DRIP_BLE_FLEET_MAX` is 1: two drones need 1.08 s per
  second at the 30 ms slot.

### `drone_playback.cpp` / `.h`
**Purpose.** Walks a recorded flight track at its recorded pace.
**Owns.** `DRONE_REPLAY_RECORDED_TIME` (**0**, configuration),
`PLAYBACK_CYCLE_S`, `PLAYBACK_MIN_DT_S`, and the per-aircraft `PlaybackState`.
**Constraints.**
- **Pacing and timestamping are separate concerns.** The recorded timestamps
  always decide which point is emitted and when, by comparing measured elapsed
  time against the recorded delta. `DRONE_REPLAY_RECORDED_TIME` decides only
  which value is written into the Location timestamp field. Setting it to 1 puts
  two clocks in one pack and breaks the synchronisation 14 CFR §89.310(b)
  requires; it does not change the replay speed.
- Elapsed time is **measured** with `millis()`, never assumed from the nominal
  cycle, so pacing self-corrects when the fleet size changes.
- At the end of a track playback holds on the final point rather than wrapping.
  Wrapping would teleport the aircraft back to takeoff mid-broadcast.

### `drone_data.h`
**Purpose.** The flight tracks, in program memory. **(session 3)** 5 flights:
- 0 and 1: synthetic boxes `BOX-SJC` and `BOX-AZ`;
- 2 to 4: the former recorded flights 24 to 26, with their points
  byte-identical.

Generated by `make_box_flights.py` from the previous file.
**Constraints.** `DroneFlight.det` is unused: identity is per slot, not per
flight. The original generator (`csv_to_drone_data.py`) is not in the project.
The removed flights 0 to 23 exist only in the old `drone_data.h`.

### Identities and chains **(session 3, part 7)**
**Where.**
- `det_generator.cpp`: `IDENTITY_TABLE`, 6 rows (`DET_IDENTITY_COUNT`),
  separate from the 3 radio slots (`DET_IDENTITY_SLOTS`, `FLEET_MAX`).
- `drip_hierarchy.h`: chains A, B and C.
- `drip_registration.cpp`: signs chains A and C, and each slot's leaf.
- `drone_fleet.cpp`: `g_slot_ident[]` and the `identity` command.

**Constraints.**
- Identities 3 (malformed DET) and 5 (bad endorsement) are faulty **on
  purpose**, marked by `DET_FLAG_*`. Identity 3's boot check reports an error
  if its fault disappears.
- Chain C and identities 3-5 must stay **out** of `hierarchy.json`;
  `check_hierarchy.py` section 5 fails if chain C appears there.
- `COMMANDS.md` §1.9 is the human-readable list of every entity's DET and keys,
  recomputed from the seeds.

### `rid_transport.cpp` / `.h` **(session 3)**
**Purpose.** The runtime radio selector. The fleet calls only this module.
**Constraints.** Bluetooth is brought up on the first `radio bt`, never at boot,
so a Bluetooth failure leaves the board on Wi-Fi. Only one radio transmits at a
time. On Wi-Fi every call passes straight to `beacon_tx_raw`, so the Wi-Fi bytes
are identical to the build before it existed.

### `ble_tx.cpp` / `.h`, `ble_frame.cpp` / `.h` **(session 3)**
**Purpose.** Bluetooth Legacy advertising through Bluedroid (`ble_tx`), and the
pure ASTM Table 14 framing, 31 octets (`ble_frame`).
**Constraints.**
- `ble_tx.cpp` includes `esp32-hal-bt-mem.h`. Without it arduino-esp32 3.3.7+
  frees the controller memory at boot and the controller can never start.
- One advertising set (BT 4.2): changing drone means stop, new address, start.
- The random static address cannot change while advertising.
- No BLE 5 feature is used; this silicon has none (ESP32-D0WD-V3).

### `beacon_tx_raw.cpp` / `.h`
**Purpose.** Builds and injects the 802.11 beacon frames. **(session 3)**
`suspend()` / `resume()` stop and restart Wi-Fi around a Bluetooth session.
**Owns.** The per-slot MAC addresses and the channel.
**Constraints.** Frames are hand-built and injected with driver sequence
numbering disabled, so sequence numbers are synthesised per identity. An access
point path was evaluated and removed: an access point holds one BSSID and
therefore cannot represent three independent aircraft.

### `cshake128.cpp` / `.h`
**Purpose.** cSHAKE128, for DET derivation and Manifest hashing.
**Constraints.** Must agree byte for byte with `det.py` on the Observer side.
`check_hierarchy.py` is what proves they still do.

### `drip_debug.cpp` / `.h`, `flight_sim.cpp` / `.h`, `message_pack.cpp` / `.h`
**Purpose.** The gated pack hex dump, a synthetic route kept for single-drone
smoke tests, and the ASTM Message Pack assembler.
**Constraints.** The dump is gated to one slot for the bandwidth reason above.
`message_pack` enforces the nine-message limit of Table 13.

---

## 3. Firmware sniffer

### `DRIP_Sniffer/DRIP_Sniffer.ino`
**Purpose.** Captures the air interface and prints it to serial.
**Owns.** `SNIFFER_CHANNEL` (6), `SNIFFER_BAUD` (921600), `RING_SLOTS` (16),
`MAX_FRAME` (512), `BEACON_TAGGED_START` (36), the ODID vendor OUI and type, and
the capture output format.
**Depends on.** The ESP-IDF promiscuous receive path. Nothing in this folder.
**Constraints.**
- It never transmits. Its value is that what it prints actually propagated.
- The output is hand-shaped to be importable by `text2pcap` without a radiotap
  header, which is why an ESP32 is used rather than a monitor-mode adapter.
  `odid.py` parses the same format and starts the 802.11 payload at offset 36.
  Change the header layout here and `odid.parse_format_a()` must change with it.
- The sixteen-slot ring can overflow. The firmware reports its own captured,
  dropped and oversize counts every ten seconds, and those counts belong in the
  denominator of any reception figure.
- **(session 3)** `radio wifi|bt|status` switches at runtime; the board boots on
  Wi-Fi and Format A is unchanged. Bluetooth is a passive Bluedroid scan, 100 %
  duty, duplicate filter OFF, printed as Format BT. The `# stats` line gained a
  trailing ` radio=wifi|bt`, appended so existing regexes still match. The same
  memory-header rule and Huge APP partition as the transmitter apply.

---

## 4. The Observer

### `observer.py`
**Purpose.** Decodes a capture, applies the error catalogue, and prints the
report. Also carries the single-identifier resolution and registry commands.
**Owns.**
- `APEX_HI` and `APEX_DET`, the fallback trust anchor, and `load_hierarchy()`,
  which replaces them from the trust file. The pair must satisfy its own binding;
  `_selftest_anchor()` announces it at import if it does not.
- `TS_RANGE`, the valid authentication timestamp range. **Derived**, from the
  limitation ASTM F3411-22a Table 8 prints: 01/01/2019 to 01/19/2087 is
  `2**31 - 1` seconds, so the bound is signed-32-bit wide even though the field
  is 32 bits. Do not widen it to `2**32 - 1`; that makes `E-AUTH-06` unreachable.
- `Keyring`, and with it the rule that a key enters only through `add()`, which
  re-derives the DET and refuses the pair when it does not hold.
- `KeyOrigin` and the four provenance constants. `ANCHOR_SOURCES` decides which
  provenances may start the endorsement walk, and `SRC_AIR` is deliberately not
  among them.
- `DeferredChecks`, the queue of evidence awaiting a key, and the rule that a
  DET still keyless after the walk yields one `E-KEY-01` stating its coverage.
- `verify_link_chain()`, the anchored traversal.
- `verify_manifests()`, the per-aircraft Manifest ledger.
- The command-line interface.
**Depends on.** `odid.py`, `errors.py`, and optionally `det.py`, `ed25519.py`,
`ed25519_backend.py`, `identity_resolve.py`, `identity_lookup.py`. Every one of
the optional imports degrades to a disabled check rather than a crash.
**Constraints.**
- **Never relax the two insertion rules.** A key enters the keyring only after
  its binding to the DET is verified at the point of insertion, and a key
  learned from an endorsement is admitted only when that endorsement's chain
  reaches an anchor the Observer already held. Either relaxation turns the trust
  model into self-assertion.
- Trust flows downward only. Resolving a parent key from any endorsement present
  accepts two entities that endorse each other, which is the defect the anchored
  traversal exists to remove.
- An endorsement that fails `E-LINK-01` or `E-LINK-04` must not teach a key.
- `run()` returns exactly three values. `make_vectors.py` unpacks three.
- A key learned from the air is valid for the run that learned it. There is no
  automatic path that writes one into the trust file.

### `odid.py`
**Purpose.** Parsing only. ASTM message and pack layout, DRIP auth page
reassembly, and the capture formats. **(session 3)** Format BT
(`parse_format_bt`, `parse_bt_record`, `split_capture_segments` for mixed
files), RFC 9575 §5 FEC (`fec_expected_pages`, `fec_check`, `fec_recover`), and
`LegacyAssembler`, which groups pages by (address, counter), drops repeated
copies, and closes a message when complete or rebuildable. Figure 12's
pseudocode is not followed where it contradicts the §5.2 prose.
**Owns.** `MSG_LEN` (25), `PROTO_VERSION`, `MSG_TYPES`, `SAM_TYPES`,
`DET_PREFIX`, `EPOCH_2019` (1546300800), the format detectors, the format
parsers, `split_pack()`, `decode_message()`, `reassemble_auth()`,
`decode_link_sam()`, `decode_manifest_sam()` and
`reconstruct_wrapper_evidence()`.
**Depends on.** The standard library only.
**Constraints.**
- It performs no validation and emits no finding. Judgement belongs in
  `observer.py`. Keeping the two apart is what lets the reference encoder test
  the Observer against the specification rather than against the parser.
- Every format detector is a positive test. An unrecognised file is refused.
  Format B must never become the unconditional fallback again: an air capture
  decoded as flat hex produced ten thousand findings on a clean file.
- `EPOCH_2019` is the ODID epoch. Timestamps inside DRIP structures are raw
  DRIP-epoch seconds and are **not** offset by it on decode. Anything comparing
  them against a Unix time must convert.

### `errors.py`
**Purpose.** The error catalogue and the `Finding` type.
**Owns.** `ERROR_CATALOG`: 35 codes prefixed `E-` and 2 prefixed `W-`, each with
a description and the clause it derives from. **(session 3)** `E-FEC-01` to
`E-FEC-04` (RFC 9575 §5.1, §6.1, §6.2); `E-SEM-01` and `E-MAN-02` descriptions
extended for Legacy.
**Depends on.** Nothing.
**Constraints.**
- The `E-` and `W-` prefixes carry meaning and must stay distinct. `E-` asserts
  that a named clause was violated. `W-` asserts something about this bench and
  nothing about any standard. A capture-pipeline fault reported as `E-` would
  attribute a serial-link problem to the aircraft.
- A code added here needs a check that raises it and a vector that exercises it,
  or it is an assertion about the Observer that nothing tests.
- The catalogue is the source for Section 3.7 of the dissertation. Changing a
  description or a clause means changing that table.

### `det.py`
**Purpose.** The shared identity module: DET construction and the DET-to-key
binding.
**Owns.** The Keccak permutation, `shake128()`, `cshake128()`, `CONTEXT_ID`,
`compute_det()`, `parse_det()`, `verify_det_binding()`, the RFC 9374 Appendix C
Base32 alphabet, and the recorded test identity `UA_DET` / `UA_PUB`.
**Depends on.** The standard library only.
**Constraints.**
- `HOST_ID` is the **raw** 32-byte public key, not the 4-byte-wrapped HIP
  parameter. This matches the RFC 9374 reference generator and the deployed
  registry, and was verified against a live DET. Changing it changes every
  identifier on the bench.
- Field positions are fixed by RFC 9374 §3.3: prefix 0-27, RAA 28-41, HDA 42-55,
  Suite 56-63, hash 64-127. **Derived** from those: the HDA boundary at bit 56
  is a multiple of four and the RAA boundary at bit 42 is not.
- Run `python det.py` after any change. It checks the Keccak core against
  `hashlib`, the NIST cSHAKE128 sample, and the RFC 9374 Appendix B.1 example.

### `ed25519.py`
**Purpose.** The RFC 8032 reference implementation, in pure Python.
**Owns.** `derive_pubkey()`, `sign()`, `verify()`.
**Depends on.** The standard library only.
**Constraints.** This is the normative reference. It is slow by about three
orders of magnitude and that is acceptable, because its role is to be the thing
the fast backend is proved against. Do not optimise it.

### `ed25519_backend.py`
**Purpose.** Selects a faster Ed25519 implementation and proves it before use.
**Owns.** The backend choice, the startup self-test, `backend_name()`,
`selftest_note()`, `force_pure_python()`, and the memoisation of verified
`(key, message, signature)` triples.
**Depends on.** `ed25519.py`, and optionally `cryptography`.
**Constraints.**
- A faster backend is adopted only after agreeing with `ed25519.py` on RFC 8032
  §7.1 TEST 1 in both the valid and the tampered case. A backend that fails is
  not used, and the Observer says which backend it is using at startup.
- The memoisation is safe only because re-verifying an identical triple cannot
  change the answer. The roughly 10 Hz beacon repeat makes it worth having.

### `identity_resolve.py`
**Purpose.** Offline resolution of one DET against the trust file. No network.
**Owns.** `TrustStore`, `load_trust()`, `resolve_det()`, `Resolution`,
`iter_known_keys()`, `zone_of()`, `det_to_ptr_fqdn()`, and the constants
`RAA_ZONE_BITS` (44) and `HDA_ZONE_BITS` (56).
**Depends on.** `det.py`, optionally.
**Constraints.**
- `iter_known_keys()` is the **single source** of the Observer's keyring. There
  is no hard-coded identity table anywhere. Do not reintroduce one.
- **An RAA owns four /44 zones, not one** (RFC 9886 §6.2.1.3: the RAA borrows
  the upper two bits of HDA space). Trust in an RAA is therefore decided by the
  RAA number the DET carries, never by containment inside the single /44 derived
  from the RAA entity's own DET. That entity carries HDA 0 and sits in the first
  of the four zones, so a containment test rejects every aircraft whose HDA does
  not begin with two zero bits.
- The verdict is layered and is never a bare "valid". Structure, allow-list
  membership and the cryptographic binding are three different questions with
  three different data requirements, and the report has to say which held.
- The module performs no I/O beyond reading the trust file it is handed.

### `identity_lookup.py`
**Purpose.** Resolving a DET through DNS.
**Owns.** `DEFAULT_DNS_SERVER`, the PTR-then-TXT scheme, `TXT_KEYS`,
`parse_txt_record()`, `lookup_det()`, `DnsIdentity`, `to_ua_entry()`, and the
pluggable `Resolver` interface with its real and mock implementations.
**Depends on.** `det.py` optionally, `dnspython` when the real resolver is used.
**Constraints.**
- **The two-hop PTR-then-TXT scheme is a divergence from RFC 9886 §5.1 and
  §5.2**, which specify HHIT (RRType 67) and BRID (RRType 68) records carrying
  certificate-based content. The server belongs to a collaborating researcher
  and the scheme cannot be changed from here. It is a reportable finding, not a
  defect to hide.
- DNSSEC handling is **presence only**. An RRSIG being present is reported as
  `dnssec_present` and never as validated. A forged answer with a bogus RRSIG
  would pass. Do not rename the field to anything that reads as validation.
- A key from DNS goes through the same binding check as any other key.

---

## 5. The live path

Present in `ObserverRealTime/` only. It is a monitoring aid. The authoritative
result is always a batch `observer.py` run over the finished capture.

### `live_feed.py`
**Purpose.** Tails a capture file that is still being written and yields
completed frames, and **(session 3)** one `("bt", record)` event per Format BT
advertisement, parsed by `odid.parse_bt_record()`.
**Owns.** The incremental framing state and the file-rotation detection.
**Depends on.** `odid.py`, whose compiled regexes it imports.
**Constraints.** A frame is closed when the next frame's offset-0 row appears,
which is exactly `odid.parse_format_a()`'s rule. Closing earlier on the declared
byte count saves one frame of latency and makes the live and batch paths
disagree about what a frame is.

### `live_state.py`
**Purpose.** Accumulates the model the page shows, from frames fed one at a time.
**Owns.** `Drone`, `LiveState`, the stale and drop policy, the incremental
Manifest and endorsement state, the finding aggregation, and `time_override`.
**Depends on.** `observer.py`, `odid.py`, `flight_tracks.py`, `errors.py`,
`make_map.py`.
**Constraints.**
- Per-frame validation calls `observer.process_payload()`. It does not
  re-implement any check.
- **(session 3)** RFC 9575 Appendix A: `auth_state()` (pure), `FAIL_CODES`,
  `AUTH_STATES`. The evidence counters live on `Drone`. A state change needs
  only `auth_state()` and its truth table. `E-LINK-03` is pending, not failure.
  `confirm()` holds the operator's §6.4.2 assertion in memory only.
- **(session 3, T58)** The Appendix A colour is judged on a **window**: the
  last complete endorsement cycle (`_chain_path`, `_note_link_rx`,
  `Drone.window_start`). Evidence is timed (`Drone.ev`). A change to what
  counts for the colour is made in `_auth_state_of` only.
- **(session 3, T59)** `E-MAN-04` comparability is
  `observer.manifest_pair_comparable()`, shared by batch and live, for both
  transports.
- **(session 3, T57)** The live chain verdict judges only the newest
  endorsement per (child, parent) (`_current_bes()`). The batch report judges
  them all. So the two may differ on a renewed endorsement: live shows the
  current state, batch shows the history.
- **(session 3)** `ingest_bt()` uses the batch judge's own
  `observer.new_legacy_context()` / `process_legacy_event()`, and the same
  Legacy rules for E-MAN-02/03/04 (`observer.LEGACY_MAN_GAP_US`). E-SEM-01 over
  Legacy is batch-only: it needs the whole capture.
- The endorsement verdict is **replaced** on each recomputation, never
  accumulated. A child endorsement received before its parent legitimately
  reports a broken chain for as long as the chain is still being collected, and
  counting those transients would be meaningless.
- Its `DeferredChecks` keeps still-keyless entries on the queue rather than
  reporting `E-KEY-01`, because live an absent key may simply not have arrived.
- `time_override` is test-only. It moves the reference time for `E-LINK-04` and
  `E-FRESH-01` and nothing else. Staleness always uses the real host clock,
  because "am I hearing this aircraft now" is a question about the world. Any
  run with it set is a bench exercise, never evidence, and it is announced on
  the terminal, carried in the snapshot and banner-flagged on the page.

### `live_observer.py`
**Purpose.** Wires the feed, the state and the server together against a capture
file already being written. Does not open the serial port.
**Depends on.** `live_feed.py`, `live_state.py`, `live_server.py`, `observer.py`.
**Constraints.** Builds its keyring exactly as `observer.py`'s `main()` does, so
the two cannot diverge in what they trust.

### `live_server.py`
**Purpose.** Serves the page and the snapshot.
**Owns.** The three routes: `/`, `/state.json`, `/set-time`.
**Depends on.** The standard library only, deliberately.
**Constraints.** Binds to loopback by default. The snapshot carries aircraft
positions and identities.

### `live_map.html`
**Purpose.** The page. Read from disk on each request so it can be edited
without a restart.
**(session 3)** The marker shows the RFC 9575 Appendix A state, the track the
identity. The page holds no state logic: the state, its colour and the legend
come from `/state.json`. The "Confirmed by observation" button posts to
`/confirm`.

### `run_live.py`
**Purpose.** Starts the capture and the live view together, and stops both.
**Owns.** The timestamped default capture name.
**Constraints.** `arduino_logger.py` opens its output with mode `w`, which
truncates. The timestamped name exists so that starting a session cannot destroy
the previous one. Do not make a fixed name the default.

### `replay_test.py`
**Purpose.** Replays a finished capture through the live path on the capture's
own timeline, to check the live and batch paths agree. A harness, not a
deliverable.
**Constraints.** Must close the feed before unlinking its temporary file.
Windows refuses to unlink an open file.

---

## 6. Analysis tooling

### `make_vectors.py`
**Purpose.** The reference encoder, and the Observer's self-test.
**Owns.** The hand-built ASTM and DRIP message builders, the structural vector
set, the endorsement-chain vectors, the Manifest vectors, the five
trust-model vectors C1 to C5, and **(session 3)** the 13 Bluetooth Legacy / FEC
vectors: an independent `fec_scatter()` written from RFC 9575 §5.1, Format BT
output of the §6.4 schedule, and a mixed Wi-Fi + Bluetooth capture. 51 checks
in total.
**Depends on.** `odid.py`, `observer.py`, `det.py`, `ed25519.py`.
**Constraints.**
- It builds messages **from the specification layouts**, not from the firmware.
  That is the whole point: it tests the Observer against the standard rather than
  against the transmitter. Do not import a firmware constant here.
- A vector asserts the exact code expected. The trust-model vectors additionally
  assert the provenance of the key and that no key was learned where none should
  have been, because an Observer that stopped checking would otherwise pass.
- `--now` is a Unix timestamp. Passing a DRIP-epoch value places the reference
  time in 1971 and the test fires for the wrong reason.

### `check_hierarchy.py`
**Purpose.** Proves the hierarchy is coherent and delegable. Run after any edit
to `drip_hierarchy.h` or `hierarchy.json`.
**Owns.** The four proofs: derivation, agreement between header and JSON,
RFC 9886 validity of the numbers, and that every listed authority derives with
no shared key pair.
**Depends on.** `det.py`, `ed25519.py`, `identity_resolve.py`.
**Constraints.**
- **Do not reintroduce a "/44 contains the HDA DET" test.** That is not the RFC
  rule and it rejects valid pairs such as 255/14340. The real rules are the RAA
  range, the reserved HDA values 0, 4096, 8192 and 12288, and parents and
  children carrying the same numbers.
- The header is read with regular expressions rather than parsed. If the header
  stops matching, the tool fails loudly rather than silently checking nothing.
- Exit status gates a build: 0 coherent, 1 a problem.

### `make_map.py`
**Purpose.** Plots a capture as a self-contained Leaflet page.
**Owns.** `PALETTE`, `vnb_to_iso()`, and the page template.
**Depends on.** `odid.py`, `flight_tracks.py`.
**Constraints.** Produces the file offline; viewing it fetches the library and
tiles from public services. The time shown against a point is the VNB of the
nearest DRIP authentication message, because the ASTM System message carries no
timestamp in this firmware.

### `flight_tracks.py`
**Purpose.** Folds decoded messages into per-identity tracks.
**Owns.** `extract_tracks()`, and the public wrappers `new_state()` and
`process_decoded()` that let the live path feed one pack at a time.
**Constraints.** The live map and `make_map.py` share this code so they can
never disagree about where an aircraft was. **(session 3)** On Format BT the
running identity is kept per sender address; Legacy Locations carry no VNB, so
their map time is empty.

### `bt_timing.py` **(session 3)**
**Purpose.** Measures the Bluetooth timing from a Format BT capture: copy
spacing, copies per message, loss per type from counter gaps, refresh gaps
against BUR0010 and the 3 s static limit, Authentication completeness.
**Constraints.** A measurement tool: it raises no code and verifies no
signature. Its timestamps carry host-stack jitter, and a gap at the receiver
includes reception losses; it says so in its output.

### `arduino_logger.py`
**Purpose.** Captures a serial stream to a file without resetting the board.
**Owns.** The default port `COM4`, the default rate 115200, the default output
`data_log.txt`, and the DTR and RTS suppression.
**Depends on.** `pyserial`.
**Constraints.**
- Opening a port normally toggles DTR and RTS, which are wired to EN and GPIO0,
  rebooting the board and losing the selected flight. The suppression is the
  reason this tool exists.
- The read loop is written for the sniffer's rate. Printing every line at 921600
  stalls the reader, the operating-system buffer overflows and bytes are
  discarded silently. `--echo` is for 115200 only.
- Output mode is `w`, which truncates.

### `newkey.py`
**Purpose.** Generates one identity: seed, public key, DET.
**Constraints.** The seed it prints is a private key. It exists to be pasted
into firmware and must not be committed anywhere public.

---

## 7. Data files

### `hierarchy.json`
**Purpose.** The trusted-identities file, and the Observer's single source of
key material. **Public data only.**
**Owns.** The Apex, the RAA and HDA entries of both chains, and the `ua` array.
**Constraints.**
- Every DET here must derive from the `public_key` beside it. The Observer
  refuses an entry that does not, entry by entry, and announces it.
- `ua_raa` and `ua_hda` at the top name the chain currently flown. They must
  agree with `DRIP_UA_RAA` and `DRIP_UA_HDA` in `drip_hierarchy.h`.
- An entry may omit `public_key`. That gives allow-list membership with no
  binding check, which is the correct representation of an identity registered
  elsewhere whose key this bench does not hold.
- It is written by the Observer when the operator answers yes to a prompt. It is
  never written without one.
- Run `check_hierarchy.py` after editing it.

### `drip_hierarchy.h`
**Purpose.** The firmware half of the hierarchy, and the only firmware file
here.
**Owns.** `DRIP_UA_RAA` (255) and `DRIP_UA_HDA` (14340) as **configuration**;
the Apex, RAA and HDA numbers of both chains, three of which are **derived** by
`#define` from the UA numbers; and the five private seeds.
**Constraints.**
- The seeds are **published private keys**. They are test material and provide
  no security. A real deployment holds none of them: the registries sign the
  endorsements offline and only the public halves ever reach an aircraft.
- The compile-time assertions hold the parents' numbers equal to the aircraft's.
  A hierarchy whose numbers do not nest passes every offline signature check and
  cannot be delegated in DNS, so the guard sits outside the signature path.
- Chain A and chain B must keep distinct seeds. Sharing them gives the two RAAs
  one key pair and the two HDAs another, and one chain becomes a relabelling of
  the other. `check_hierarchy.py` fails on a shared public key.
- Section 3 of the header is informational. It records derived values and is not
  an input.

### `bench.keyring`, `newchain.keyring`
**Purpose.** Optional `DET_HEX PUBKEY_HEX` pairs for `--keyring`.
**Constraints.** They add to the trust file rather than replacing it. Each pair
goes through the same binding check on insertion.

### `capture*.txt`, `CaptureWithDNS*.txt`
**Purpose.** Stored captures. They are the regression corpus: every one is
reprocessed before and after a change to the Observer, and the reports compared.
**Constraints.**
- `capture.txt` was recorded by a superseded firmware build. Its endorsements
  name an Apex this work no longer uses and its child DETs do not derive from
  the public keys carried beside them. It is expected to report `E-LINK-01` and
  `E-LINK-03`. Keep it: it is the only capture that exercises the Observer
  against a chain that is genuinely broken.
- `data_log.txt` is **not** a capture. The Observer refuses it, which is correct.

---

## 8. Configuration against derived values

| Value | Kind | Owner |
|---|---|---|
| `DRIP_UA_RAA` = 255, `DRIP_UA_HDA` = 14340 | configuration | `drip_hierarchy.h` |
| Apex, RAA and HDA numbers of chain A | derived from the UA numbers | `drip_hierarchy.h` |
| Chain B numbers 1000 and 2000 | configuration | `drip_hierarchy.h` |
| The five private seeds | configuration | `drip_hierarchy.h` |
| Every public key and every DET | derived from a seed and the numbers | recomputed by `check_hierarchy.py` |
| `APEX_HI` / `APEX_DET` in `observer.py` | fallback configuration, overridden by the trust file | `observer.py` |
| `SNIFFER_CHANNEL` = 6, `SNIFFER_BAUD` = 921600 | configuration | `DRIP_Sniffer.ino` |
| `BEACON_TAGGED_START` = 36 | derived from the 802.11 beacon header layout | `DRIP_Sniffer.ino`, mirrored in `odid.py` |
| `EPOCH_2019` = 1546300800 | fixed by ASTM F3411-22a | `odid.py` |
| `TS_RANGE` upper bound = `2**31 - 1` | derived from the Table 8 limitation | `observer.py` |
| `MSG_LEN` = 25, pack limit 9, 201-octet ceiling | fixed by the standards | `odid.py`, `observer.py` |
| `RAA_ZONE_BITS` = 44, `HDA_ZONE_BITS` = 56 | fixed by RFC 9886 §6 | `identity_resolve.py` |
| `DEFAULT_DNS_SERVER` | configuration | `identity_lookup.py` |
| `DRIP_BLE_ADV_SLOT_MS` = 30, `DRIP_BLE_ADV_INT_UNITS` = 0x20 | bench configuration, **not yet measured** | `drip_config.h` |
| `DRIP_BLE_FLEET_MAX` = 1 | configuration (author decision) | `drip_config.h` |
| Self ID / Operator ID test values | fabricated configuration | `drip_config.h`, mirrored in `make_vectors.py` |
| `BLE_SCAN_INTERVAL` = `BLE_SCAN_WINDOW` = 0x50 | configuration | `DRIP_Sniffer.ino` |
| `LEGACY_MAN_GAP_US` = 1.6 s | derived from the one-per-second §6.4 schedule | `observer.py`, used by `live_state.py` |

---

## 9. Known duplication, and what catches drift

| Duplicated | Copies | Caught by |
|---|---|---|
| The hierarchy numbers and keys | `drip_hierarchy.h`, `hierarchy.json` | `check_hierarchy.py` |
| The Python tooling | three folders | nothing; copy by hand |
| The 802.11 payload offset | `DRIP_Sniffer.ino`, `odid.py` | nothing; a mismatch mis-decodes silently |
| The error catalogue | `errors.py`, Section 3.7 of the dissertation | nothing |
| The ODID epoch | `odid.py`, `live_state.py` | nothing; `live_state.py` names it as the same value |
| The Format BT line **(session 3)** | `DRIP_Sniffer.ino`, `odid.py` (`_FMT_BT_META`), `bt_timing.py`, the MOCK_DET_DRIP fork | `make_vectors.py` writes the same line; `bt_timing.py` keeps its own regex |
| Self ID / Operator ID test values **(session 3)** | `drip_config.h`, `make_vectors.py` | checked byte for byte once (PROGRESS.md), not automatically |
