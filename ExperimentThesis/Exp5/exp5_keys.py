"""Experiment 5, Step 5: the key of each identity and where it came from.

Decodes a capture as observer.py does (same time reference rule: the
'# host-time' marker) and prints, for every key the run holds, the DET, the
origin (trust file, air, registry), the parent that endorsed it when it came
from the air, and the key in hex. Run from ObserverRealTime:

    python ..\\ExperimentThesis\\Exp5\\exp5_keys.py <capture> <trust file> [--dns-fallback]

With --dns-fallback the registry is consulted for every DET the trust file
lacks, exactly as observer.py --dns-fallback does without a terminal: a key
from the registry is used for this run only and nothing is written.
"""

import sys
import os

sys.path.insert(0, os.getcwd())
import odid                      # noqa: E402
import observer                  # noqa: E402


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    capture, anchor = argv[0], argv[1]
    dns = "--dns-fallback" in argv[2:]

    text = open(capture, encoding="utf-8", errors="replace").read()
    marker = odid.find_host_time(text)
    if marker is None:
        raise SystemExit("ERROR: the capture has no '# host-time' marker")
    observer.load_hierarchy(anchor)
    keys = observer.default_keyring(anchor)
    if dns:
        import identity_lookup
        keys.fallback = observer.DnsFallback(keys, anchor,
                                             identity_lookup.DEFAULT_DNS_SERVER,
                                             interactive=False)
    tr = observer.TimeReference(host_unix=marker[0], sniffer_us=marker[1])
    observer.run(text, keys=keys, time_ref=tr)

    print(f"\ncapture: {capture}")
    print(f"trust file: {anchor}   registry fallback: {'on' if dns else 'off'}\n")
    print(f"{'DET':40s} {'origin':10s} {'endorsed by':40s} key")
    for det_b, o in keys.origins().items():
        parent = observer._det_str(o.parent_det) if getattr(o, "parent_det", None) else "-"
        pub = keys.for_det(det_b)
        print(f"{observer._det_str(det_b):40s} {o.source:10s} {parent:40s} "
              f"{pub.hex() if pub else '-'}")


if __name__ == "__main__":
    main(sys.argv[1:])
