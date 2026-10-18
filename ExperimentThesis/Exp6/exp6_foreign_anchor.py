"""Experiment 6, Part 4: a trust anchor of another hierarchy.

Writes foreign-apex.json beside this script: a trusted-identities file that
holds one apex and nothing else. The apex is valid, its DET derives from its
public key (RFC 9374 Section 3.5.2), and it belongs to no hierarchy of the
bench: its key comes from a fixed seed that no entity of the bench uses, so
the file is the same on every run.

Run it from the ObserverRealTime folder, where det.py and ed25519.py are:

    python ..\\ExperimentThesis\\Exp6\\exp6_foreign_anchor.py
"""

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "foreign-apex.json"
SEED_LABEL = b"DRIP PoC foreign apex, Experiment 6"


def main():
    if not Path("det.py").exists():
        raise SystemExit("Run this script from the ObserverRealTime folder.")
    sys.path.insert(0, os.getcwd())
    import det
    import ed25519

    seed = det.shake128(SEED_LABEL, 32)
    pub = ed25519.derive_pubkey(seed)
    det_bytes = det.compute_det(pub, 0, 0)          # RAA 0, HDA 0, like the bench apex
    if not det.verify_det_binding(det_bytes, pub):
        raise SystemExit("ERROR: the generated apex DET does not derive from its key")

    bench = json.load(open("hierarchy.json", encoding="utf-8"))["apex"]
    if bench["det"].upper() == det_bytes.hex().upper():
        raise SystemExit("ERROR: the generated apex equals the bench apex")

    doc = {
        "_comment": "Experiment 6, Part 4. A trust anchor of another hierarchy: "
                    "a valid apex that endorses no entity of the bench. Generated "
                    "by exp6_foreign_anchor.py; PUBLIC data only.",
        "ua_raa": 0,
        "ua_hda": 0,
        "apex": {
            "raa": 0,
            "hda": 0,
            "det": det_bytes.hex().upper(),
            "public_key": pub.hex().upper(),
            "_role": "Apex of another hierarchy - endorses nothing on the bench",
        },
        "raas": [],
        "hdas": [],
        "ua": [],
    }
    OUTPUT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"apex DET   {det_bytes.hex().upper()}")
    print(f"apex key   {pub.hex().upper()}")
    print(f"bench apex {bench['det'].upper()} (different)")
    print(f"written to {OUTPUT.name}")


if __name__ == "__main__":
    main()
