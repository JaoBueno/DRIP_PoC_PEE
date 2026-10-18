"""Experiment 2, Step 6: Message Pack compositions.

Reads exp2_report_verbose.txt (the verbose Observer report of the Experiment 2
capture) from the folder this script is in, and writes exp2_compositions.txt
beside it. Every frame of a Wi-Fi Beacon capture carries one Message Pack, and
the verbose report lists the messages of each pack, so grouping those lines by
frame gives the composition of every pack. Packs with the same contents are
counted together and named after the three compositions of the transmitter.

Since every message the Observer lists comes from a Message Pack, the output
also supports the check that every message type travelled inside a pack
(ASTM F3411-22a 5.4.5.22, BMG0250).
"""

import collections
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = HERE / "exp2_report_verbose.txt"
OUTPUT = HERE / "exp2_compositions.txt"

# One line of the verbose report per message of a pack, e.g.
#   frame[0] 02:44:52:49:50:00 cnt=0x06 msg[2]: System  lat=... lon=...
MSG_LINE = re.compile(
    r"frame\[(\d+)\] \S+ cnt=\S+ msg\[\d+\]: "
    r"(Basic ID|Location/Vector|System|Authentication|Self ID|Self-ID|Operator ID)"
)

# (Basic ID, Location/Vector, System, Authentication pages, total messages)
KNOWN = {
    (1, 1, 1, 5, 8): "A: Basic ID, Location/Vector, System, five Wrapper pages",
    (1, 1, 0, 7, 9): "B: Basic ID, Location/Vector, seven Link pages",
    (1, 1, 1, 6, 9): "C: Basic ID, Location/Vector, System, six Manifest pages",
}


def main():
    if not REPORT.exists():
        raise SystemExit(f"{REPORT.name} not found in {HERE}. Run Step 3 first.")
    text = REPORT.read_text(encoding="utf-8", errors="replace")

    frames = collections.defaultdict(list)
    for frame, msg_type in MSG_LINE.findall(text):
        frames[frame].append(msg_type)

    compositions = collections.Counter(
        (m.count("Basic ID"), m.count("Location/Vector"), m.count("System"),
         m.count("Authentication"), len(m))
        for m in frames.values()
    )

    lines = ["BasicID Location System Auth Total : packs : composition"]
    for key, count in sorted(compositions.items()):
        lines.append(f"{key} : {count} : {KNOWN.get(key, 'OTHER: outside the three compositions')}")
    lines.append(f"packs in total: {sum(compositions.values())}")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUTPUT.name}")


if __name__ == "__main__":
    main()
