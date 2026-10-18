"""Experiment 5, Step 1: offline resolution of the fourteen identifiers.

Runs `observer.py --resolve` on each DET of the experiment, against the
trusted-identities file (hierarchy.json) and with no network, writes every
answer to exp5_resolve.txt beside this script, and ends with one summary line
per DET: the findings raised (E-ZONE-01, E-TRUST-01, E-KEY-01) or "none".

Run it from the ObserverRealTime folder, where observer.py and hierarchy.json
are:

    python ..\\ExperimentThesis\\Exp5\\exp5_resolve.py

It does the same as the for loop of Step 1 in EXPERIMENTS.md.
"""

import contextlib
import io
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "exp5_resolve.txt"

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

CODE = re.compile(r"\[(E-[A-Z]+-\d\d)\]")


def main():
    if not Path("observer.py").exists():
        raise SystemExit("Run this script from the ObserverRealTime folder.")
    sys.path.insert(0, os.getcwd())
    import observer

    blocks, summary = [], []
    for i, (name, det) in enumerate(DETS, 1):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = observer.main(["--resolve", det])
        text = buf.getvalue()
        codes = sorted(set(CODE.findall(text)))
        blocks.append(f"===== {i}. {name}: {det}  (exit {rc})\n{text}")
        summary.append(f"{i:2d}. {name:32s} {det:40s} {', '.join(codes) or 'none'}")

    out = "\n".join(blocks) + "\nSUMMARY (findings per DET)\n" + "\n".join(summary) + "\n"
    OUTPUT.write_text(out, encoding="utf-8")
    print(out)
    print(f"written to {OUTPUT.name}")


if __name__ == "__main__":
    main()
