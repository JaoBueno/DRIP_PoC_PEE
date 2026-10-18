"""Experiment 6, Part 2: the findings of a capture split by transmitter address.

The Observer judges each Wrapper and Manifest on its signature, and keeps one
verdict per identifier (DET): it uses no transmitter address to decide
anything. This script only REPORTS the outcome per address, so that the
impersonation table of the dissertation can be traced to a file. The address
is the source address the sniffer records for every frame (802.11 header),
which the Observer prints in the location of each finding.

For each transmitter address it prints:
  * the number of frames, and the DET(s) broadcast from that address;
  * the number of each code raised on frames from that address;
  * the number of distinct Wrapper and Manifest signatures that verified, and
    of those that failed (E-SIG-01, E-MAN-01).
Codes raised on no frame (endorsements, W-MAC-02, W-CAP-01, E-KEY-01 summaries)
are listed apart.

Run it from the ObserverRealTime folder:

    python ..\\ExperimentThesis\\Exp6\\exp6_by_address.py <capture> [trust file]

The trust file defaults to hierarchy.json. The output is written beside this
script, as <capture name>_by_address.txt.
"""

import collections
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FRAME = re.compile(r"^frame\[(\d+)\] (\S+) ")


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    if not Path("observer.py").exists():
        raise SystemExit("Run this script from the ObserverRealTime folder.")
    capture = Path(argv[0])
    anchor = argv[1] if len(argv) > 1 else "hierarchy.json"
    sys.path.insert(0, os.getcwd())
    import odid
    import observer

    text = capture.read_text(encoding="utf-8", errors="replace")
    marker = odid.find_host_time(text)
    if marker is None:
        raise SystemExit("ERROR: the capture has no '# host-time' marker")
    observer.load_hierarchy(anchor)
    keys = observer.default_keyring(anchor)
    tr = observer.TimeReference(host_unix=marker[0], sniffer_us=marker[1])
    _fmt, report, findings = observer.run(text, keys=keys, time_ref=tr)

    def mac_of(where):
        m = FRAME.match(where)
        return m.group(2) if m else None

    # frames and DETs per address
    frames = collections.Counter()
    dets = collections.defaultdict(set)
    for w, d in report:
        if d.get("type") == 0x0 and d.get("det") is not None and d.get("_mac"):
            frames[d["_mac"]] += 1
            dets[d["_mac"]].add(observer._det_str(d["det"]))

    # codes per address
    codes = collections.defaultdict(collections.Counter)
    no_frame = collections.Counter()
    failed_where = collections.defaultdict(set)
    for f in findings:
        mac = mac_of(f.where)
        if mac is None:
            no_frame[f.error_id] += 1
        else:
            codes[mac][f.error_id] += 1
            failed_where[f.error_id].add(f.where)

    # distinct signatures verified / failed per address
    wrap_ok = collections.defaultdict(set)
    wrap_bad = collections.defaultdict(set)
    man_ok = collections.defaultdict(set)
    man_bad = collections.defaultdict(set)
    seen_man = set()
    for w, d in report:
        a = d.get("_auth")
        mac = mac_of(w)
        if not a or mac is None or a.get("auth_type") != 5 or a.get("_expired"):
            continue
        sam = bytes(a.get("sam_data", b""))
        if a.get("sam_type") == 0x02 and len(sam) >= 88:
            (wrap_bad if w in failed_where["E-SIG-01"] else wrap_ok)[mac].add(sam[24:88])
        elif a.get("sam_type") == 0x03:
            if sam in seen_man:
                continue                      # the Observer checks each Manifest once
            seen_man.add(sam)
            (man_bad if w in failed_where["E-MAN-01"] else man_ok)[mac].add(sam)

    lines = [f"capture: {capture}", f"trust file: {anchor}", ""]
    for mac in sorted(frames):
        lines.append(f"address {mac}: {frames[mac]} frames, DET(s) broadcast: "
                     f"{', '.join(sorted(dets[mac]))}")
        lines.append(f"  Wrapper signatures verified {len(wrap_ok[mac])}, failed {len(wrap_bad[mac])} (distinct)")
        lines.append(f"  Manifest signatures verified {len(man_ok[mac])}, failed {len(man_bad[mac])} (distinct)")
        for code, n in sorted(codes[mac].items()):
            lines.append(f"  {code:10s} {n}")
        lines.append("")
    lines.append("codes raised on no frame (endorsements, identities, capture):")
    for code, n in sorted(no_frame.items()):
        lines.append(f"  {code:10s} {n}")
    lines.append("")
    lines.append("E-SIG-01 is counted per Wrapper frame (each Wrapper is sent twice); "
                 "E-MAN-01 per distinct Manifest.")

    out = HERE / f"{capture.stem}_by_address.txt"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {out.name}")


if __name__ == "__main__":
    main(sys.argv[1:])
