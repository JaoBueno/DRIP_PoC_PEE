"""Experiment 5, Step 2: registry lookup of the fourteen identifiers.

Runs `observer.py --dns-lookup` on each DET of the experiment, writes every
answer to exp5_dns_lookup.txt beside this script, and ends with one summary
line per DET: the domain name and "binding VERIFIED" or "binding FAILED" when
the registry holds a record, "no record" when the PTR query returned no
answer, and "no answer from the registry" when the output matches neither.
The Observer reports a timeout or an unreachable resolver with the same message
as a DET with no record ("PTR lookup returned no answer"), so a run in which no
DET returns a record ends with a warning: the registry may have been
unreachable.

The question "Write this identity into hierarchy.json?" is answered with
nothing, so the trusted-identities file is never changed.

Needs network access to the registry resolver and dnspython. Run it from the
ObserverRealTime folder:

    python ..\\ExperimentThesis\\Exp5\\exp5_dns_lookup.py

Any extra argument is passed to observer.py, for example
`--dns-server <IP>` to use another resolver. It does the same as the for loop
of Step 2 in EXPERIMENTS.md.
"""

import contextlib
import io
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "exp5_dns_lookup.txt"

DETS = [
    ("Apex", "2001:30:0:5:70f9:e8e9:b564:f448"),
    ("RAA, chain A", "2001:30:3fc0:5:9024:e82a:8fd0:afb8"),
    ("HDA, chain A", "2001:30:3ff8:405:d162:233e:9b7e:feee"),
    ("RAA, chain B", "2001:30:fa00:5:d18f:f62a:f870:d730"),
    ("HDA, chain B", "2001:30:fa07:d005:f0d2:b5a:871b:a28"),
    ("RAA, chain C", "2001:3f:0:5:80a:9f96:d49f:7057"),
    ("HDA, chain C", "2001:3f:0:6405:f18a:e883:952e:9b04"),
    ("UA identity 0", "2001:30:3ff8:405:d952:5618:fbc9:c3cf"),
    ("UA identity 1", "2001:30:3ff8:405:8412:4323:5d3c:a050"),
    ("UA identity 2", "2001:30:3ff8:405:a57e:87ab:5388:cbb8"),
    ("UA identity 3 (malformed DET)", "2001:30:3ff8:405:b113:9c81:d46a:cb85"),
    ("UA identity 4 (chain C)", "2001:3f:0:6405:b6ae:eea3:d5b:898c"),
    ("UA identity 5 (bad endorsement)", "2001:30:3ff8:405:a5c7:51d1:7b8c:6526"),
    ("Listed with no key", "2001:30:3ff8:405:5c76:7822:e2ed:15bc"),
]

FQDN = re.compile(r"FQDN\s*:\s*(\S+)")


def outcome(text):
    """One-line reading of the output of one lookup."""
    if "PTR lookup returned no answer" in text:
        return "no record"
    m = FQDN.search(text)
    if m and "BINDING: VERIFIED" in text:
        return f"{m.group(1)}  binding VERIFIED"
    if m and "BINDING: FAILED" in text:
        return f"{m.group(1)}  binding FAILED"
    if m:
        return f"{m.group(1)}  binding not checked"
    return "no answer from the registry (see the block above)"


def main(extra):
    if not Path("observer.py").exists():
        raise SystemExit("Run this script from the ObserverRealTime folder.")
    sys.path.insert(0, os.getcwd())
    import observer

    blocks, summary = [], []
    real_stdin = sys.stdin
    for i, (name, det) in enumerate(DETS, 1):
        buf = io.StringIO()
        sys.stdin = io.StringIO("")          # empty answer: nothing is written
        try:
            with contextlib.redirect_stdout(buf):
                rc = observer.main(["--dns-lookup", det] + extra)
        finally:
            sys.stdin = real_stdin
        text = buf.getvalue()
        blocks.append(f"===== {i}. {name}: {det}  (exit {rc})\n{text}")
        summary.append(f"{i:2d}. {name:32s} {det:40s} {outcome(text)}")

    out = "\n".join(blocks) + "\nSUMMARY (registry answer per DET)\n" + "\n".join(summary) + "\n"
    if not any("binding" in line for line in summary):
        # The Observer reports a timeout or an unreachable resolver with the
        # same message as a DET with no record, so a run in which no DET at
        # all returned a record cannot tell the two apart.
        out += ("\nWARNING: no DET returned a record. The Observer reports an "
                "unreachable registry with the same message as a DET with no "
                "record, so this run does not show which of the two happened. "
                "Check the connection and run the step again.\n")
    OUTPUT.write_text(out, encoding="utf-8")
    print(out)
    print(f"written to {OUTPUT.name}")


if __name__ == "__main__":
    main(sys.argv[1:])
