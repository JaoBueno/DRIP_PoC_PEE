# Experiments of the dissertation

This folder holds the procedure, the outputs and the logs of the experiments
reported in the dissertation. Each experiment has its own section in this file
and its own subfolder for the files it produces (`Exp1/`, `Exp2/`, ...).

The commands are written for the Windows **Command Prompt (cmd)**. Every
command is run from the `ObserverRealTime` folder of this repository.

---

## Before any experiment

**Requirements:** Python 3.13 or later, and the `cryptography` library, which
the Observer uses as its accelerated Ed25519 backend:

```bat
pip install cryptography
```

**Open the Command Prompt in the right folder.** Replace the path with the
place where this repository is on your computer:

```bat
cd C:\path\to\DRIP_PoC_PEE\ObserverRealTime
```

The prompt then ends in `...\DRIP_PoC_PEE\ObserverRealTime>`.

**How to read a result.** Each command is given twice: once to show the output
on the screen, and once with `>` to save the same output in a file of
`ExperimentThesis`. After a command, this prints its exit status:

```bat
echo %ERRORLEVEL%
```

`0` means the command finished with every check passed. Any other value means
at least one check failed.

---

## Experiment 1: Qualification of the instruments

**Objective.** Test the Observer and its tools against references produced
outside the bench (the layouts of ASTM F3411-22a and RFC 9575, RFC 9374
Appendix B.1, RFC 8032 Section 7.1) before any capture is decoded.

**Needs:** no ESP32 board and no network.

**Output folder:** `ExperimentThesis\Exp1\`. Create it once:

```bat
mkdir ..\ExperimentThesis\Exp1
```

### Step 1. Self-test of the reference encoder

Show the result on the screen:

```bat
python make_vectors.py --selftest
```

Save it:

```bat
python make_vectors.py --selftest > ..\ExperimentThesis\Exp1\exp1_selftest.txt
```

**Expected.** One line per case, then six summary lines:

```
self-test: 22 passed, 0 failed
  chain self-test: 5 passed, 0 failed
  manifest self-test: 6 passed, 0 failed
  trust self-test: 5 passed, 0 failed
  legacy self-test: 18 passed, 0 failed
  window self-test: 20 passed, 0 failed
```

**How to read a case.** Each line shows `[PASS]` or `[FAIL]`, the case, the
code it expects (`expect=`) and the codes the Observer raised (`got:`). A case
built to break a rule passes when the expected code is **among** the codes
raised. Other codes may appear beside it, because one defect can break more
than one rule (for example, a Message Pack that declares three messages and
carries two also contains a message shorter than 25 bytes) or can stop a later
check from succeeding (for example, an endorsement with a bad signature leaves
the endorsements below it with no path to the trust anchor). A valid case
passes only when no code is raised.

Cases T19 and T20 of the window self-test run the Observer command line. Their
`expect=` and `got:` columns hold an exit status in place of a code: `exit 2`
when the Observer refuses a capture with no time reference, and `exit 0` when it
reads a capture through its `# host-time` marker and raises no code. Section 8
of `COMMANDS.md` lists the exit statuses.

**For the dissertation:** the six summary lines fill the self-test table, and
a screenshot of the end of the run is the self-test figure.

### Step 2. Registration hierarchy

```bat
python check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json
```

```bat
python check_hierarchy.py --header drip_hierarchy.h --json hierarchy.json > ..\ExperimentThesis\Exp1\exp1_hierarchy.txt
```

**Expected.** Five numbered sections, every line ending in `OK`, and a last
line starting with `OK - the hierarchy is coherent`.

| Section of the output | What it proves |
|---|---|
| 1. DERIVATION | every identifier re-derives from its public key |
| 2. AGREEMENT | the firmware header and the trust file carry the same numbers, and the seeds produce the recorded keys |
| 3. HIERARCHY VALIDITY | the RAA and HDA numbers lie in the allocated ranges and avoid the reserved HDA values |
| 4. ALL CHAINS | no public key is held by two authorities |
| 5. CHAIN C | the chain reserved for learning from the air is absent from the trust file |

### Step 3. Identity module

```bat
python det.py
```

```bat
python det.py > ..\ExperimentThesis\Exp1\exp1_det.txt
```

**Expected.** The first line is:

```
self-test OK (Keccak, NIST cSHAKE128 KAT, HID packing, DET round-trip + binding)
```

`det.py` stops at the first failed check, so this line appears only when every
check holds. An `AssertionError` means a check failed.

### Step 4. Signature backend

```bat
python -c "import ed25519_backend as b; print(b.backend_name()); print(b.selftest_note())"
```

```bat
python -c "import ed25519_backend as b; print(b.backend_name()); print(b.selftest_note())" > ..\ExperimentThesis\Exp1\exp1_backend.txt
```

**Expected.** Two lines, the first naming the backend and the second ending in
`(valid accepted, tampered rejected)`, for example:

```
cryptography 47.0.0 (OpenSSL)
agrees with ed25519.py on RFC 8032 §7.1 TEST 1 (valid accepted, tampered rejected)
```

If the first line reads `ed25519.py (pure python reference)`, the accelerated
library was not found or did not agree with the reference implementation, and
the Observer falls back to the pure Python one.

**Backend announced by the Observer.** The Observer prints the same two facts
at the start of every run. To see them without a capture from the air, write
the encoder's vectors to a file and read that file:

```bat
python make_vectors.py --write ..\ExperimentThesis\Exp1\exp1_vectors.txt
```

```bat
python observer.py ..\ExperimentThesis\Exp1\exp1_vectors.txt --now 1715853817 > ..\ExperimentThesis\Exp1\exp1_observer_start.txt
```

The vectors carry no receive time, so `--now` gives the Observer one fixed time
at which every validity window is judged. `1715853817` is 60 s after the VNB of
the valid Wrapper vector, which places it inside its window. Without `--now` the
Observer refuses the file with exit status `2` (section 3.3 of `COMMANDS.md`).

The first four lines of `exp1_observer_start.txt` name the trust anchor, the
Ed25519 backend, the result of its self-test and the time reference. The rest
of the file is the report on the vectors, which contain broken cases on purpose,
so its findings are expected and this one command ends with `%ERRORLEVEL%`
equal to `1`.

### Files produced

| File | Content |
|---|---|
| `Exp1\exp1_selftest.txt` | every case of the self-test and the six summary lines |
| `Exp1\exp1_hierarchy.txt` | the five sections of the hierarchy check |
| `Exp1\exp1_det.txt` | the identity module check |
| `Exp1\exp1_backend.txt` | the signature backend and its self-test |
| `Exp1\exp1_vectors.txt` | the vectors written by the encoder |
| `Exp1\exp1_observer_start.txt` | the Observer run on those vectors |

### If a check fails

Keep the output file and do not change the code before recording it. A failed
case is reported separately in the dissertation, with the case, the code
expected and the codes raised, and every later result that depends on that
check is held until the check is corrected and Experiment 1 is repeated.

---
---

## Experiment 2: Carriage and structural conformance

**Objective.** Show, from a capture of the air interface, that a broadcast
carrying DRIP authentication remains a conforming ASTM F3411-22a Wi-Fi Beacon
broadcast: no structural finding, every message inside a Message Pack, the
pages of each Authentication message in one pack, every pack in one of the
three compositions (A, B, C), and every DRIP payload within nine pages and 201
octets (RFC 9575 Section 3.2.4.2).

**Needs:** both ESP32 boards flashed with the current firmware (transmitter:
`DRIP_Broadcast_RID.ino`; sniffer: `DRIP_Sniffer.ino`), both connected by USB,
and the Arduino IDE to type the transmitter commands. No network.

**Output folder:** `ExperimentThesis\Exp2\`. It holds the two analysis scripts
of Steps 5 and 6, `exp2_formats.py` and `exp2_compositions.py`, and every file
of this experiment is written beside them. If the folder holds files from an
earlier run, move them to a subfolder first: the commands below overwrite them.

**Find the two serial ports.** In the Arduino IDE, *Tools > Port* lists the
COM port of each board (or use the Windows Device Manager, *Ports (COM &
LPT)*). Below, `COMT` is the transmitter port and `COMS` is the sniffer port.
Replace them with the real names, for example `COM3` and `COM4`.

### Step 1. Prepare the transmitter

Get the current time in Unix seconds:

```bat
python -c "import time; print(int(time.time()))"
```

Open the Arduino IDE Serial Monitor on `COMT` at **115200** baud and press the
reset button of the transmitter board. Then type, one line at a time (replace
`<unix>` with the number printed above):

```text
time <unix>
fleet 1
fleet set 0 2
identity
radio
```

What each line does and what to check in the answer:

| Typed | Effect | Check |
|---|---|---|
| `time <unix>` | sets the clock and re-signs the endorsement chain | `[Time]` shows today's date and "endorsement chain re-signed" |
| `fleet 1` | one aircraft | the fleet table shows one slot |
| `fleet set 0 2` | slot 0 replays flight 2, a recorded real flight | the fleet table shows flight 2 on slot 0 |
| `identity` | shows the identity of slot 0 | identity 0 (valid, chain A) |
| `radio` | shows the active radio | Wi-Fi Beacon |

The order matters. A reset returns the board clock to 2026-01-01, and every
Wrapper, Manifest and Link signed before `time` carries that date. The
Observer judges each of them against the time it was received, so they would
fall outside their validity windows (`E-WIND-01`, `E-LINK-04`).

In the fleet table, the column `phase` shows the cycle the aircraft is in at
that moment (A Wrapper, B Link, C Manifest). It changes every second.

Keep this Serial Monitor open: Step 7 uses it.

### Step 2. Capture the air

Close any Serial Monitor open on `COMS`. In the Command Prompt, from
`ObserverRealTime`:

```bat
python arduino_logger.py --port COMS --baud 921600 -o ..\ExperimentThesis\Exp2\exp2_capture.txt
```

The tool prints `Connected without resetting the board` and one progress line
per second. Leave it running for **10 to 15 minutes**, then press **Ctrl+C**.
Write down the duration.

`-o` overwrites an existing file: use a new name if you repeat the capture.

When it reads the first frame, the logger writes one line before it:
`# host-time unix=... sniffer_us=...`. The Observer uses this line to give every
frame its receive time, at which it checks the validity windows. Confirm that
the capture holds exactly one such line:

```bat
findstr /B /C:"# host-time" ..\ExperimentThesis\Exp2\exp2_capture.txt
```

### Step 3. Decode the capture

Short report (summary, capture health, findings):

```bat
python observer.py ..\ExperimentThesis\Exp2\exp2_capture.txt > ..\ExperimentThesis\Exp2\exp2_report.txt
```

Verbose report (every frame, every message, every reassembled Authentication
message):

```bat
python observer.py ..\ExperimentThesis\Exp2\exp2_capture.txt --verbose > ..\ExperimentThesis\Exp2\exp2_report_verbose.txt
```

Open `exp2_report.txt` and read:

- `Time reference: '# host-time' marker ...`: the receive times come from the
  marker of Step 2. If the Observer prints `ERROR: no time reference` and exits
  with `2`, the capture has no marker (section 3.3 of `COMMANDS.md`);
- `Capture health: N/N frames intact`: frames damaged on the host
  (`W-CAP-01`) are the difference;
- `Message-type counts`: Basic ID, Location/Vector, System and Authentication
  (each Authentication page counts once);
- `Findings`: the structural codes are those starting with `E-FMT`,
  `E-PACK`, `E-AUTH`, `E-SAM`, `E-SEM` and `E-FEC`. Experiment 2 expects none.
  Codes about keys, endorsements, evidence and validity windows (`E-KEY`,
  `E-LINK`, `E-MAN`, `E-SIG`, `E-WIND`) belong to Experiments 4 to 6 and are
  not judged here.

To list only the structural findings:

```bat
findstr /C:"E-FMT" /C:"E-PACK" /C:"E-AUTH" /C:"E-SAM" /C:"E-SEM" /C:"E-FEC" ..\ExperimentThesis\Exp2\exp2_report.txt > ..\ExperimentThesis\Exp2\exp2_structural.txt
```

An empty `exp2_structural.txt` means no structural finding.

### Step 4. Sniffer losses

The sniffer writes a `# stats` line every ten seconds with its cumulative
counters since boot:

```bat
findstr /B /C:"# stats" ..\ExperimentThesis\Exp2\exp2_capture.txt > ..\ExperimentThesis\Exp2\exp2_stats.txt
```

In `exp2_stats.txt`, the frames captured, dropped and oversize **during the
capture** are the values of the last line minus those of the first line.

### Step 5. Formats, pages and Length

Run the script `exp2_formats.py`, which is in the Experiment 2 results folder:

```bat
python ..\ExperimentThesis\Exp2\exp2_formats.py
```

It reads `exp2_report_verbose.txt` from its own folder, prints the result and
writes it to `exp2_formats.txt` in the same folder. The output has one line per
format and size, and a last line counting the incomplete messages, for example:

```
DRIP Link | 7 pages | 137 octets | 587 messages | within limit: yes
DRIP Manifest | 6 pages | 121 octets | 588 messages | within limit: yes
DRIP Wrapper | 5 pages | 89 octets | 589 messages | within limit: yes
incomplete: 0
```

Every line must read `within limit: yes` (at most **9 pages and 201 octets**,
RFC 9575 Section 3.2.4.2), and `incomplete` must be `0`: an Authentication
message is complete only when all its pages arrived in its pack, which also
shows that they shared the pack's Message Counter.

### Step 6. Pack compositions

Run the script `exp2_compositions.py`, which is in the same folder:

```bat
python ..\ExperimentThesis\Exp2\exp2_compositions.py
```

It reads `exp2_report_verbose.txt` from its own folder, prints the result and
writes it to `exp2_compositions.txt` in the same folder. Each line counts the
packs with the same contents and names their composition, for example:

```
BasicID Location System Auth Total : packs : composition
(1, 1, 0, 7, 9) : 587 : B: Basic ID, Location/Vector, seven Link pages
(1, 1, 1, 5, 8) : 589 : A: Basic ID, Location/Vector, System, five Wrapper pages
(1, 1, 1, 6, 9) : 588 : C: Basic ID, Location/Vector, System, six Manifest pages
packs in total: 1764
```

A line marked `OTHER` is a pack outside the three compositions. The total
should equal the number of frames intact in `exp2_report.txt`. Since every
message listed by the Observer comes from a Message Pack, the output also shows
that every message type travelled inside a pack.

### Step 7. Pack dump for the figure

In the transmitter Serial Monitor (Step 1), type:

```text
debug on
```

Wait about five seconds, so that one pack of each cycle (A, B, C) is printed,
then type:

```text
debug off
```

Copy the printed packs from the Serial Monitor and save them as
`ExperimentThesis\Exp2\exp2_packdump.txt`.

### Files produced

| File | Content |
|---|---|
| `Exp2\exp2_capture.txt` | the air capture, with its `# host-time` line |
| `Exp2\exp2_report.txt` | the Observer report |
| `Exp2\exp2_report_verbose.txt` | the verbose report |
| `Exp2\exp2_structural.txt` | the structural findings (empty when none) |
| `Exp2\exp2_stats.txt` | the sniffer statistics lines |
| `Exp2\exp2_formats.py` | analysis script of Step 5 (part of the repository) |
| `Exp2\exp2_formats.txt` | messages, pages and Length per DRIP format |
| `Exp2\exp2_compositions.py` | analysis script of Step 6 (part of the repository) |
| `Exp2\exp2_compositions.txt` | packs per composition |
| `Exp2\exp2_packdump.txt` | one pack of each composition, from the transmitter |

Keep `exp2_capture.txt`: Experiments 3 and 4 use the same transmission.  --APENAS

---
---

PLACEHOLDER EXPERIMENT 3

---
---

## Experiment 4: Verification from the air

**Objective.** Show that the Observer, with no network access, reaches a verdict
on each aircraft from the air interface alone: the identifier binds to its key
(RFC 9374 Section 3.5.2), every endorsement verifies under its parent and lies
within its validity window (RFC 9575 Sections 4.2 and 3.2.4.3), the Wrapper and
the Manifest are received within their windows and verify under the endorsed
key (RFC 9575 Sections 4.3 and 4.4), and the chain reaches a trusted identity
(RFC 9575 Section 6.4.2). Each capture is decoded twice: with the complete
trusted-identities file and with a file holding the Apex alone.

**Needs:** the capture of Experiment 2 (`Exp2\exp2_capture.txt`), both ESP32
boards for one new capture of three aircraft, and the Arduino IDE. No network:
the registry fallback (`--dns-fallback`) stays off, which is its default.

**Output folder:** `ExperimentThesis\Exp4\`. Create it once:

```bat
mkdir ..\ExperimentThesis\Exp4
```

### Step 1. The two trusted-identities files

The complete file is `hierarchy.json` in `ObserverRealTime`. It holds the Apex,
the RAAs and HDAs of chains A and B, and the aircraft identities 0, 1 and 2.

Build the Apex-only file from it, with the RAA, HDA and aircraft lists emptied:

```bat
python -c "import json; h=json.load(open('hierarchy.json')); [h.__setitem__(k, []) for k in ('raas','hdas','ua')]; json.dump(h, open(r'..\ExperimentThesis\Exp4\apex-only.json','w'), indent=2)"
```

Check both files:

```bat
python observer.py --list-keys > ..\ExperimentThesis\Exp4\exp4_keys_complete.txt
python observer.py --anchor ..\ExperimentThesis\Exp4\apex-only.json --list-keys > ..\ExperimentThesis\Exp4\exp4_keys_apex.txt
```

**Expected.** `exp4_keys_apex.txt` starts with `Keyring: 1 DET-bound key(s)`
and lists only the Apex, `2001:30:0:5:70f9:e8e9:b564:f448`.
`exp4_keys_complete.txt` starts with Keyring: 8 DET-bound key(s) and lists the Apex, two RAAs, two HDAs and the three aircraft (identities 0, 1 and 2).

### Step 2. One aircraft: the capture of Experiment 2

In this step we run the capture from Experiment 2 twice, once with the trusted identities from the file on STEP 1, using the hierarchy.json that is in the Observer folder, and later using the apex-ony.json that is in the "Experiment 4" folder. With the complete file, every key the verdict needs is already known. With the Apex-only file, the Observer starts from the Apex key alone and has to learn the keys of the RAA, of the HDA and of the aircraft from the DRIP Links received on the air.

Complete file:

```bat
python observer.py ..\ExperimentThesis\Exp2\exp2_capture.txt > ..\ExperimentThesis\Exp4\exp4_1ua_complete.txt
```

Apex alone:

```bat
python observer.py ..\ExperimentThesis\Exp2\exp2_capture.txt --anchor ..\ExperimentThesis\Exp4\apex-only.json > ..\ExperimentThesis\Exp4\exp4_1ua_apex.txt
```

### Step 3. Three aircraft: a new capture

Get the current time in Unix seconds:

```bat
python -c "import time; print(int(time.time()))"
```

Open the Arduino IDE Serial Monitor on `COMT` at **115200** baud, press the
reset button of the transmitter board and type (replace `<unix>`):

```text
time <unix>
```

A reset returns every slot to identity `i` on slot `i` (identities 0, 1 and 2,
all of chain A).

Close any Serial Monitor open on `COMS` and start the logger, from
`ObserverRealTime`:

```bat
python arduino_logger.py --port COMS --baud 921600 -o ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt
```

With the logger running, type in the transmitter Serial Monitor:

```text
fleet 3 same 2
fleet
```

`fleet 3 same 2` starts three aircraft, each in its own slot with its own
address, all replaying flight 2, with the Message Counter at 0 and a new
Manifest ledger, and re-signs the endorsement chain. `fleet` lists them:

| Check in the fleet table | Expected |
|---|---|
| slots | 0, 1 and 2 |
| MAC | `02:44:52:49:50:00`, `...:01`, `...:02` |
| id | 0, 1 and 2 |
| flight | 2 on every slot |

Leave the logger running for **10 to 11 minutes** (flight 2 lasts about 11.7
minutes; after its last point an aircraft leaves the air), then press
**Ctrl+C**. Confirm the time marker:

```bat
findstr /B /C:"# host-time" ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt
```

Exactly one line is expected.

### Step 4. Three aircraft: decode

Similar to Step 2, here we want to run the capture results against the hierarchy.json that is in the Observer folder, and later using the apex-ony.json that is in the "Experiment 4" folder.

Complete file:

```bat
python observer.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt > ..\ExperimentThesis\Exp4\exp4_3ua_complete.txt
```

Apex alone:

```bat
python observer.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt --anchor ..\ExperimentThesis\Exp4\apex-only.json > ..\ExperimentThesis\Exp4\exp4_3ua_apex.txt
```

Sniffer losses of the new capture, as in Experiment 2, Step 4:

```bat
findstr /B /C:"# stats" ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt > ..\ExperimentThesis\Exp4\exp4_stats_3ua.txt
```

### Step 5. Read the four reports

In each of `exp4_1ua_complete.txt`, `exp4_1ua_apex.txt`,
`exp4_3ua_complete.txt` and `exp4_3ua_apex.txt`:

- `Time reference: '# host-time' marker ...`: the windows were judged at the
  receive time of each frame;
- `Capture health`: frames intact;
- **identity table**, one row per aircraft: the column `key from` gives the
  origin of its key (`trust file (slot N)` or `air (endorsed by <HDA DET>)`),
    and the column `auth` reads `OK (W wrap, M man)`: `OK` means the Observer
  holds a key for the DET, and W and M are the distinct Wrapper and Manifest
  signatures received under it. They are the signatures verified only when no
  `E-SIG-01` or `E-MAN-01` is raised for that DET. Each pack is sent twice, so
  each signature is counted once;
- `Key provenance`: the count of keys by origin;
- `Findings by DET` and `Findings`.

The four checks of each identity, and the codes that would contradict them:

| Check | Codes |
|---|---|
| the identifier binds to its key | `E-DET-02`, `E-LINK-01` |
| every endorsement verifies and lies within its window | `E-LINK-02`, `E-LINK-04` |
| the Wrapper and the Manifest are received within their windows, verify, and the ledger holds | `E-WIND-01`, `E-SIG-01`, `E-MAN-01` to `E-MAN-05` |
| the chain reaches a trusted identity | `E-LINK-03`, `E-KEY-01` |

**Expected key provenance:**

| Run | Line |
|---|---|
| one aircraft, complete | `Key provenance: 8 from trust file` |
| one aircraft, Apex alone | `Key provenance: 1 from trust file, 3 from air` (RAA, HDA, aircraft) |
| three aircraft, complete | `Key provenance: 8 from trust file` |
| three aircraft, Apex alone | `Key provenance: 1 from trust file, 5 from air` (RAA, HDA, three aircraft) |

The complete file holds eight keys (Apex, two RAAs, two HDAs, three aircraft);
the summary counts every key of the run, used or not. A key from the registry
would mean the run used the network.

**Codes expected from the bench transmitter** 

- The capture of Experiment 2 raises one `E-MAN-02` on frame 2: the
  transmission had been halted with `stop` and resumed with the logger
  recording, and the first Manifest references the last Wrapper pack built
  before the halt, which the capture does not hold.
- In the three-aircraft capture, aircraft `i` starts at phase `i`, so slot 1
  starts in Cycle B and slot 2 in Cycle C. Their first Manifest is built before
  any Wrapper pack (slot 1) or any Link and Wrapper pack (slot 2) of the new
  ledger, and carries null hashes (`0000000000000000`). Expected from the
  firmware: one `E-MAN-02` for slot 1, and one `E-MAN-02` and one `E-MAN-03`
  for slot 2, on their first Manifest only.
- A finding present under the Apex-only file and absent under the complete
  file means the offline path depends on prior enrolment of the aircraft.

### Files produced

| File | Content |
|---|---|
| `Exp4\apex-only.json` | the trusted-identities file with the Apex alone |
| `Exp4\exp4_keys_complete.txt` | the keyring of the complete file |
| `Exp4\exp4_keys_apex.txt` | the keyring of the Apex-only file |
| `Exp4\exp4_1ua_complete.txt` | one aircraft, complete file |
| `Exp4\exp4_1ua_apex.txt` | one aircraft, Apex alone |
| `Exp4\exp4_capture_3ua.txt` | the three-aircraft capture, with its `# host-time` line |
| `Exp4\exp4_stats_3ua.txt` | the sniffer statistics lines of that capture |
| `Exp4\exp4_3ua_complete.txt` | three aircraft, complete file |
| `Exp4\exp4_3ua_apex.txt` | three aircraft, Apex alone |
|


---
---

## Experiment 5: Registry resolution

**Objective.** Show what resolution through the registry adds, when
connectivity exists, to the verdict the Observer reaches from the air. The
same identifiers are resolved against the trusted-identities file (offline)
and against the registry (DNS), and the three-aircraft capture of Experiment 4
is decoded with the registry fallback armed.

**How the registry is used.** The registry is the collaborating researcher's
DNS server, `141.227.148.117`. It answers a PTR query on the reverse name of a
DET with a domain name, and a TXT query on that name with the registration data
and the public key. RFC 9886 Sections 5.1 and 5.2 specify the HHIT and BRID
records instead, which would add a registration certificate and the Broadcast
Endorsements; this server publishes neither, so the Observer checks only that
the key derives the DET (RFC 9374 Section 3.5.2). The answers are not signed
(no DNSSEC), and the dissertation reads them under two assumptions: channel
authenticity and registry integrity. A negative answer concerns only the zone
this server serves.

**Needs:** network access to `141.227.148.117` (DNS, port 53), `dnspython`
(`pip install dnspython`), and two files of Experiment 4:
`Exp4\apex-only.json` and `Exp4\exp4_capture_3ua.txt`. No new transmission.

**Output folder:** `ExperimentThesis\Exp5\`. **Create it first**, before any
step:

```bat
mkdir ..\ExperimentThesis\Exp5
```

The folder need to holds the three scripts of this experiment, which are part of the repository: `exp5_resolve.py` (Step 1), `exp5_dns_lookup.py` (Step 2) and `exp5_keys.py` (Step 5). If they are missing, copy them into it. Every file of this experiment is written beside them.

**Script or direct command.** Steps 1 and 2 can be run either with their script or with the `for` loop given below them, whichever the person running the experiment prefers. Both run the same Observer command on the same fourteen DETs. The script writes the output file itself and ends it with a summary line per DET; the loop writes the raw output only.

**The identifiers.** Steps 1 and 2 use the same fourteen DETs:

| # | Entity | DET |
|---|---|---|
| 1 | Apex | `2001:30:0:5:70f9:e8e9:b564:f448` |
| 2 | RAA, chain A | `2001:30:3fc0:5:9024:e82a:8fd0:afb8` |
| 3 | HDA, chain A | `2001:30:3ff8:405:d162:233e:9b7e:feee` |
| 4 | RAA, chain B | `2001:30:fa00:5:d18f:f62a:f870:d730` |
| 5 | HDA, chain B | `2001:30:fa07:d005:f0d2:b5a:871b:a28` |
| 6 | RAA, chain C | `2001:3f:0:5:80a:9f96:d49f:7057` |
| 7 | HDA, chain C | `2001:3f:0:6405:f18a:e883:952e:9b04` |
| 8 | UA identity 0 | `2001:30:3ff8:405:d952:5618:fbc9:c3cf` |
| 9 | UA identity 1 | `2001:30:3ff8:405:8412:4323:5d3c:a050` |
| 10 | UA identity 2 | `2001:30:3ff8:405:a57e:87ab:5388:cbb8` |
| 11 | UA identity 3 (malformed DET) | `2001:30:3ff8:405:b113:9c81:d46a:cb85` |
| 12 | UA identity 4 (chain C) | `2001:3f:0:6405:b6ae:eea3:d5b:898c` |
| 13 | UA identity 5 (bad endorsement) | `2001:30:3ff8:405:a5c7:51d1:7b8c:6526` |
| 14 | listed in `hierarchy.json` with no key | `2001:30:3ff8:405:5c76:7822:e2ed:15bc` |

### Step 1. Offline resolution against the trust file

**Option A, script:**

```bat
python ..\ExperimentThesis\Exp5\exp5_resolve.py
```

It writes `exp5_resolve.txt` and ends it with `SUMMARY (findings per DET)`,
one line per DET with the codes raised, or `none`.

**Option B, direct command** (one line; delete `exp5_resolve.txt` before
running it again, since `>>` appends):

```bat
for %d in (2001:30:0:5:70f9:e8e9:b564:f448 2001:30:3fc0:5:9024:e82a:8fd0:afb8 2001:30:3ff8:405:d162:233e:9b7e:feee 2001:30:fa00:5:d18f:f62a:f870:d730 2001:30:fa07:d005:f0d2:b5a:871b:a28 2001:3f:0:5:80a:9f96:d49f:7057 2001:3f:0:6405:f18a:e883:952e:9b04 2001:30:3ff8:405:d952:5618:fbc9:c3cf 2001:30:3ff8:405:8412:4323:5d3c:a050 2001:30:3ff8:405:a57e:87ab:5388:cbb8 2001:30:3ff8:405:b113:9c81:d46a:cb85 2001:3f:0:6405:b6ae:eea3:d5b:898c 2001:30:3ff8:405:a5c7:51d1:7b8c:6526 2001:30:3ff8:405:5c76:7822:e2ed:15bc) do python observer.py --resolve %d >> ..\ExperimentThesis\Exp5\exp5_resolve.txt
```

`--resolve` reads `hierarchy.json` and touches no network. For each DET it
prints the RAA and HDA, whether their zones are trusted, whether the
identifier is enrolled, whether a key is on file and whether that key derives
the DET, then a `SUMMARY` line and its findings:

| Code | Meaning |
|---|---|
| `E-ZONE-01` | the DET falls under no trusted RAA or HDA zone |
| `E-TRUST-01` | the DET is in the trust file at no level |
| `E-KEY-01` | no key on file for this DET |

### Step 2. Registry lookup

**Option A, script:**

```bat
python ..\ExperimentThesis\Exp5\exp5_dns_lookup.py
```

It writes `exp5_dns_lookup.txt` and ends it with
`SUMMARY (registry answer per DET)`, one line per DET: the domain name with
`binding VERIFIED` or `binding FAILED`, or `no record`.

**Option B, direct command** (one line; delete `exp5_dns_lookup.txt` before
running it again):

```bat
for %d in (2001:30:0:5:70f9:e8e9:b564:f448 2001:30:3fc0:5:9024:e82a:8fd0:afb8 2001:30:3ff8:405:d162:233e:9b7e:feee 2001:30:fa00:5:d18f:f62a:f870:d730 2001:30:fa07:d005:f0d2:b5a:871b:a28 2001:3f:0:5:80a:9f96:d49f:7057 2001:3f:0:6405:f18a:e883:952e:9b04 2001:30:3ff8:405:d952:5618:fbc9:c3cf 2001:30:3ff8:405:8412:4323:5d3c:a050 2001:30:3ff8:405:a57e:87ab:5388:cbb8 2001:30:3ff8:405:b113:9c81:d46a:cb85 2001:3f:0:6405:b6ae:eea3:d5b:898c 2001:30:3ff8:405:a5c7:51d1:7b8c:6526 2001:30:3ff8:405:5c76:7822:e2ed:15bc) do python observer.py --dns-lookup %d < nul >> ..\ExperimentThesis\Exp5\exp5_dns_lookup.txt
```

For each DET the Observer asks for the PTR record of its reverse name, then
for the TXT record of the name returned, and checks that the key in that
record derives the DET. `< nul` answers the question "Write this identity into
hierarchy.json?" with nothing, so the trust file is never changed.

| In `exp5_dns_lookup.txt` | Meaning |
|---|---|
| `FQDN`, `TXT record` and `BINDING: VERIFIED` | registered, and the registry key derives the DET |
| `BINDING: FAILED` | registered, and the registry key does not derive the DET |
| `PTR lookup returned no answer` | no record for that DET, **or** the registry did not answer |

The Observer reports a timeout or an unreachable registry with the same
message as a DET with no record. UA identity 0 is the control: if it also
shows `PTR lookup returned no answer`, the registry did not answer, and the
step must be repeated once the connection is back. The script prints a
`WARNING` in that case.

`DNSSEC : no RRSIG in answer` means the answer was not signed.

**Expected** (trial lookup of 2026-10-17): only UA identity 0 is registered,
as `snfr2025000123.driplab.example.`, `reg_status active`, binding verified,
`DNSSEC : no RRSIG in answer`. The other thirteen return no PTR answer.

### Step 3. The registry during a decode, Apex-only file

```bat
type nul | python observer.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt --anchor ..\ExperimentThesis\Exp4\apex-only.json --dns-fallback > ..\ExperimentThesis\Exp5\exp5_3ua_apex_dns.txt
```

is looked up in the registry once. `type nul |` is required: it gives the
Observer an input that is not a terminal, so the Observer uses a key from the
registry for this run only, asks nothing and writes nothing. `< nul` does not
work here, because Windows reports the `nul` device as a terminal: the
Observer then asks the question, reads an empty answer and declines the key.
Answering `w` at the prompt would write the identity into `apex-only.json`,
the file Experiment 4 depends on.

**Expected:**
- a `[DNS]` block for UA identity 0, ending in `DET<->key binding VERIFIED`
  and `verifying this run with the DNS key`;
- a `[DNS]` block each for identities 1 and 2, ending in
  `no identity found in DNS`;
- in the identity table, identity 0 with `key from` = `registry
  (snfr2025000123.driplab.example.)` and identities 1 and 2 with keys from the
  air, all three `OK`;
- `Key provenance: 1 from trust file, 4 from air, 1 from registry`, followed
  by the note that keys from the registry make the run network-dependent.

The registry is asked for identity 0 at its first Basic ID, before the walk
over the Links, so its key comes from the registry and the Link no longer has
to supply it.

### Step 4. Control: complete file

```bat
type nul | python observer.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt --dns-fallback > ..\ExperimentThesis\Exp5\exp5_3ua_complete_dns.txt
```

**Expected:** no `[DNS]` line, since every DET of the capture is in
`hierarchy.json`, and `Key provenance: 8 from trust file`, as in
`Exp4\exp4_3ua_complete.txt`.

### Step 5. The key from the registry against the key from the Link

The reports of Steps 3 and 4 give the origin of each key, and the script
`exp5_keys.py` prints the keys themselves. From the Link, Apex-only file, no
network:

```bat
python ..\ExperimentThesis\Exp5\exp5_keys.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt ..\ExperimentThesis\Exp4\apex-only.json > ..\ExperimentThesis\Exp5\exp5_keys_air.txt
```

From the registry, Apex-only file, registry fallback armed:

```bat
python ..\ExperimentThesis\Exp5\exp5_keys.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt ..\ExperimentThesis\Exp4\apex-only.json --dns-fallback > ..\ExperimentThesis\Exp5\exp5_keys_dns.txt
```

Each file ends with one line per key: DET, origin, the parent that endorsed it
when it came from the air, and the key in hex.

**Expected:** the line of UA identity 0, `2001:30:3ff8:405:d952:5618:fbc9:c3cf`,
reads `air` with parent `2001:30:3ff8:405:d162:233e:9b7e:feee` in
`exp5_keys_air.txt` and `registry` in `exp5_keys_dns.txt`, with the same key
in both, `f505704eb544f861190f2d8edac9ba83f320d5e38726b3f51c220851320ec7e6`.


### Files produced

| File | Content |
|---|---|
| `Exp5\exp5_resolve.txt` | offline resolution of the fourteen DETs |
| `Exp5\exp5_dns_lookup.txt` | registry lookup of the fourteen DETs |
| `Exp5\exp5_3ua_apex_dns.txt` | three-aircraft capture, Apex-only file, registry fallback armed |
| `Exp5\exp5_3ua_complete_dns.txt` | the same capture, complete file, registry fallback armed (control) |
| `Exp5\exp5_keys_air.txt` | the keys of the Apex-only run, from the Link |
| `Exp5\exp5_keys_dns.txt` | the keys of the Apex-only run with the registry fallback |

---
---

## Experiment 6: Rejection of unsubstantiated identities

**Objective.** Show that the Observer rejects an aircraft that asserts what it
cannot substantiate. Each part presents one false assertion and records the
code with which the Observer rejects it:

| Part | False assertion | How it is produced |
|---|---|---|
| 1 | defective identities: identity 3 (malformed DET) and identity 5 (altered endorsement) | console commands |
| 2 | impersonation: aircraft 1 claims the identity of aircraft 0 | a firmware image built for this part |
| 3 | evidence out of date | the transmitter clock left unset |
| 4 | a trust anchor of another hierarchy | a trusted-identities file, no capture |

**Needs:** both ESP32 boards, the Arduino IDE (to type the transmitter
commands and, for Part 2, to build and upload the firmware), and three files
of Experiment 4: `Exp4\apex-only.json`, `Exp4\exp4_capture_3ua.txt` and
`Exp4\exp4_3ua_complete.txt`. No network.

**Output folder:** `ExperimentThesis\Exp6\`. **Create it first**, before any
step:

```bat
mkdir ..\ExperimentThesis\Exp6
```

The folder needs to hold the two scripts of this experiment, which are part of the repository: `exp6_foreign_anchor.py` (Part 4) and `exp6_by_address.py` (Part 2). If they are missing, copy them into it. Every file of this experiment is written beside them.

**Ports.** As in Experiment 2: `COMT` is the transmitter port and `COMS` the sniffer port. Replace them with the real names.

**Order of the steps.** Parts 1, 3 and 4 use the current firmware, and Part 2
needs a firmware image built for it. The steps below run Parts 1, 3 and 4
first, then Part 2, and end by restoring the current firmware, so the
transmitter is uploaded twice in total.

### Step 1. Part 1: capture of the defective identities

Get the current time in Unix seconds:

```bat
python -c "import time; print(int(time.time()))"
```

Open the Serial Monitor on `COMT` at **115200** baud, press the reset button of
the transmitter and type, one line at a time:

```text
time <unix>
fleet 3 same 2
focus 1
identity 3
focus 2
identity 5
focus 0
fleet
```

`identity` acts on the focused slot, so the lines above give slot 1 identity 3
and slot 2 identity 5; slot 0 keeps identity 0, the control. The fleet table
must show:

| slot | MAC | id | flight |
|---|---|---|---|
| 0 | `02:44:52:49:50:00` | 0 | 2 |
| 1 | `02:44:52:49:50:01` | 3 | 2 |
| 2 | `02:44:52:49:50:02` | 5 | 2 |

Start the logger, from `ObserverRealTime`:

```bat
python arduino_logger.py --port COMS --baud 921600 -o ..\ExperimentThesis\Exp6\exp6_defective_capture.txt
```

With the logger running, type in the transmitter Serial Monitor:

```text
fleet 3 same 2
```

It restarts the three aircraft with the same identities (the identity of each
slot is kept across `fleet`), each with its Message Counter at 0 and a new
Manifest ledger, and re-signs the endorsement chain. Leave the logger running
for **12 minutes**, then press **Ctrl+C**, and confirm the time marker:

```bat
findstr /B /C:"# host-time" ..\ExperimentThesis\Exp6\exp6_defective_capture.txt
```

Decode it with each trusted-identities file:

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_defective_capture.txt > ..\ExperimentThesis\Exp6\exp6_defective_complete.txt
```

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_defective_capture.txt --anchor ..\ExperimentThesis\Exp4\apex-only.json > ..\ExperimentThesis\Exp6\exp6_defective_apex.txt
```

Sniffer statistics:

```bat
findstr /B /C:"# stats" ..\ExperimentThesis\Exp6\exp6_defective_capture.txt > ..\ExperimentThesis\Exp6\exp6_defective_stats.txt
```

**Expected,** under both files:

| Identity | DET | Codes |
|---|---|---|
| 0 | `2001:30:3ff8:405:d952:5618:fbc9:c3cf` | none; `OK` |
| 3 | `2001:30:3ff8:405:b113:9c81:d46a:cb85` | `E-LINK-01`, `E-KEY-01`; `NO KEY` |
| 5 | `2001:30:3ff8:405:a5c7:51d1:7b8c:6526` | `E-LINK-02`, `E-KEY-01`; `NO KEY` |

Slots 1 and 2 start in Cycles B and C, so their first Manifest also raises the
start-of-ledger codes seen in Experiment 4 (`E-MAN-02`, and `E-MAN-03` for
slot 2), with the null hash `0000000000000000`.

### Step 2. Part 3: capture with the clock unset

Press the reset button of the transmitter and **do not** type `time`. Check
the clock:

```text
time
```

It must read `(NOT set - build default...)`, with a date of 2026-01-01.

Start the logger:

```bat
python arduino_logger.py --port COMS --baud 921600 -o ..\ExperimentThesis\Exp6\exp6_stale_capture.txt
```

With the logger running, type in the transmitter Serial Monitor:

```text
fleet set 0 2
```

Slot 0 (identity 0) restarts on flight 2 with a new Manifest ledger, and the
endorsement chain is signed again with the unset clock. Leave the logger
running for **3 minutes**, press **Ctrl+C**, and confirm the time marker:

```bat
findstr /B /C:"# host-time" ..\ExperimentThesis\Exp6\exp6_stale_capture.txt
```

The marker carries the real host time, so the Observer judges every item at
its real receive time, months after the date the transmitter signed.

Decode it three times:

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_stale_capture.txt > ..\ExperimentThesis\Exp6\exp6_stale_complete.txt
```

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_stale_capture.txt --anchor ..\ExperimentThesis\Exp4\apex-only.json > ..\ExperimentThesis\Exp6\exp6_stale_apex.txt
```

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_stale_capture.txt --max-age 60 > ..\ExperimentThesis\Exp6\exp6_stale_maxage.txt
```

```bat
findstr /B /C:"# stats" ..\ExperimentThesis\Exp6\exp6_stale_capture.txt > ..\ExperimentThesis\Exp6\exp6_stale_stats.txt
```

**Expected:**

| Run | Codes |
|---|---|
| complete file | `E-WIND-01` on every Wrapper and Manifest (discarded), `E-LINK-04` on every endorsement; no Wrapper or Manifest verified |
| Apex alone | the same, plus `E-LINK-03` (the expired upper endorsements teach no key, so the lower ones have no path to the Apex) and `E-KEY-01`; no key learned from the air |
| complete file, `--max-age 60` | the codes of the first run, plus `E-FRESH-01` on every Authentication message |

### Step 3. Part 4: trust anchor of another hierarchy

Build the trusted-identities file:

```bat
python ..\ExperimentThesis\Exp6\exp6_foreign_anchor.py
```

It writes `Exp6\foreign-apex.json`, which holds one valid apex (its DET derives
from its key) of a hierarchy with no entity of the bench, and prints its DET,
`2001003000000005B18B78FF405AC2E9`. The file is the same on every run.

Decode the three-aircraft capture of Experiment 4 with it:

```bat
python observer.py ..\ExperimentThesis\Exp4\exp4_capture_3ua.txt --anchor ..\ExperimentThesis\Exp6\foreign-apex.json > ..\ExperimentThesis\Exp6\exp6_anchor_foreign.txt
```

**Expected:** `Trust anchor: ..\ExperimentThesis\Exp6\foreign-apex.json
apex=2001:30:0:5:b18b:78ff:405a:c2e9`; `E-LINK-03` on each of the five
endorsements (Apex to RAA, RAA to HDA, HDA to each of the three aircraft);
`E-KEY-01` and `NO KEY` for the three aircraft; `Key provenance: 1 from trust
file`. The start-of-ledger codes of Experiment 4 remain on aircraft 1 and 2.

### Step 4. Part 2: impersonation

**4.1 Build the adversarial firmware.** In the Arduino IDE, open
`DRIP_Fleet_Broadcast\DRIP_Broadcast_RID\DRIP_Broadcast_RID.ino`. In the tab
`drip_config.h`, find the line

```c
// #define DRIP_TEST_IMPERSONATION
```

and delete the `// ` at its start, so it reads

```c
#define DRIP_TEST_IMPERSONATION
```

Leave `DRIP_IMPERSONATOR_SLOT` at `1u` and `DRIP_IMPERSONATED_SLOT` at `0u`.
Select the transmitter port `COMT` and upload. Uploading resets the board.

With this image, slot 1 broadcasts the DET of slot 0 in its Basic ID and in
every signed structure, retransmits the genuine DRIP Link of slot 0, and signs
its Wrapper and Manifest with its own key (identity 1), from its own address
`02:44:52:49:50:01`.

**4.2 Capture.** Get the current time in Unix seconds, open the Serial Monitor
on `COMT` at 115200 baud and type:

```text
time <unix>
```

Start the logger:

```bat
python arduino_logger.py --port COMS --baud 921600 -o ..\ExperimentThesis\Exp6\exp6_imperson_capture.txt
```

With the logger running, type:

```text
fleet 2 same 2
fleet
```

The fleet table shows slots 0 and 1 with identities 0 and 1; the table lists
the identity each slot holds, and the DET that slot 1 broadcasts is the one of
slot 0. Leave the logger running for **5 minutes**, press **Ctrl+C**, and
confirm the time marker:

```bat
findstr /B /C:"# host-time" ..\ExperimentThesis\Exp6\exp6_imperson_capture.txt
```

**4.3 Decode:**

```bat
python observer.py ..\ExperimentThesis\Exp6\exp6_imperson_capture.txt > ..\ExperimentThesis\Exp6\exp6_imperson_complete.txt
```

```bat
findstr /B /C:"# stats" ..\ExperimentThesis\Exp6\exp6_imperson_capture.txt > ..\ExperimentThesis\Exp6\exp6_imperson_stats.txt
```

The control is `Exp4\exp4_3ua_complete.txt`, already produced with the current
firmware: identities 0 and 1 on addresses `:00` and `:01`, both `OK`.

**4.4 Findings by transmitter address.** The Observer keeps one verdict per
identifier and do not use the transmitter address to decide anything. To show which transmitter raised each code, the script `exp6_by_address.py` decodes the capture again and reports the outcome per address, taken from the source address the sniffer records for every frame:

```bat
python ..\ExperimentThesis\Exp6\exp6_by_address.py ..\ExperimentThesis\Exp6\exp6_imperson_capture.txt
```

It writes `Exp6\exp6_imperson_capture_by_address.txt`, with, for each address,
the frames, the DET broadcast, the distinct Wrapper and Manifest signatures
that verified and that failed, and the count of each code. `E-SIG-01` is
counted per Wrapper frame (each Wrapper is sent twice) and `E-MAN-01` per
distinct Manifest.

The `auth` column of the identity table reads `OK` whenever the Observer holds
a key for the DET, and its counts are the distinct signatures received under
that DET, verified or not. In this capture they add the signatures of both
transmitters, so the counts per address come from this step.

**Expected:**
- one identity, `2001:30:3ff8:405:d952:5618:fbc9:c3cf`, from the two addresses
  `02:44:52:49:50:00` and `02:44:52:49:50:01`, with `W-MAC-02`;
- its key from the trust file, its endorsement chain verified (no `E-LINK`
  code) and its binding verified (no `E-DET-02`);
- `E-SIG-01` on the Wrappers and `E-MAN-01` on the Manifests sent from
  `:01`, signed with the key of identity 1;
- the Wrappers and Manifests sent from `:00` still verified, and none from   `:01` (Step 4.4);
- `E-MAN-04` on the Manifests of both addresses: the two transmitters keep two   Manifest ledgers under one DET, and the Observer keeps one ledger per DET;
- the start-of-ledger code of slot 1 (`E-MAN-02` with the null hash), as in
  Experiment 4.

### Step 5. Restore the current firmware

In `drip_config.h`, put the `// ` back at the start of the line:

```c
// #define DRIP_TEST_IMPERSONATION
```

and upload again. **Do not skip this step**: every other experiment, and any
later use of the bench, needs the current firmware.

To confirm, run `fleet 2 same 2` and a short capture of one minute decoded with
`observer.py`: the identity table must list two identities, 0 and 1, and no
`W-MAC-02`.

### Files produced

| File | Content |
|---|---|
| `Exp6\exp6_foreign_anchor.py` | script of Part 4 (part of the repository) |
| `Exp6\exp6_by_address.py` | script of Part 2, Step 4.4 (part of the repository) |
| `Exp6\exp6_defective_capture.txt` | Part 1 capture, identities 0, 3 and 5 |
| `Exp6\exp6_defective_complete.txt` | Part 1, complete file |
| `Exp6\exp6_defective_apex.txt` | Part 1, Apex-only file |
| `Exp6\exp6_defective_stats.txt` | Part 1, sniffer statistics |
| `Exp6\exp6_imperson_capture_by_address.txt` | Part 2, findings and signatures per transmitter address |
| `Exp6\exp6_stale_capture.txt` | Part 3 capture, clock unset |
| `Exp6\exp6_stale_complete.txt` | Part 3, complete file |
| `Exp6\exp6_stale_apex.txt` | Part 3, Apex-only file |
| `Exp6\exp6_stale_maxage.txt` | Part 3, complete file, `--max-age 60` |
| `Exp6\exp6_stale_stats.txt` | Part 3, sniffer statistics |
| `Exp6\foreign-apex.json` | Part 4, trust anchor of another hierarchy |
| `Exp6\exp6_anchor_foreign.txt` | Part 4, Experiment 4 capture with that anchor |
| `Exp6\exp6_imperson_capture.txt` | Part 2 capture, adversarial firmware |
| `Exp6\exp6_imperson_complete.txt` | Part 2, complete file |
| `Exp6\exp6_imperson_stats.txt` | Part 2, sniffer statistics |

