"""Experiment 2, Step 5: DRIP formats, pages and Length.

Reads exp2_report_verbose.txt (the verbose Observer report of the Experiment 2
capture) from the folder this script is in, and writes exp2_formats.txt beside
it. Each output line gives one DRIP format with one size, as the number of
pages and the Length in octets, and how many reassembled messages had that
size. The last line counts the messages the Observer marked incomplete.

The limit to check is RFC 9575 Section 3.2.4.2: at most nine pages and a
Length of at most 201 octets. A message is complete only when all its pages
arrived in its Message Pack, so "incomplete: 0" also supports the check that
the pages of each Authentication message share one Message Counter
(ASTM F3411-22a 5.4.4.2, BUR0060).
"""

import collections
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = HERE / "exp2_report_verbose.txt"
OUTPUT = HERE / "exp2_formats.txt"

# One line of the verbose report per reassembled Authentication message, e.g.
#   ... Auth reassembled  type=5 pages=[0, 1, 2, 3, 4] len=89 SAM=DRIP Wrapper complete=True
AUTH_LINE = re.compile(r"pages=\[([^\]]*)\] len=(\d+) SAM=(DRIP \w+)")

PAGE_LIMIT = 9
LENGTH_LIMIT = 201


def main():
    if not REPORT.exists():
        raise SystemExit(f"{REPORT.name} not found in {HERE}. Run Step 3 first.")
    text = REPORT.read_text(encoding="utf-8", errors="replace")

    sizes = collections.Counter(
        (sam, len(pages.split(",")), int(length))
        for pages, length, sam in AUTH_LINE.findall(text)
    )
    incomplete = text.count("complete=False")

    lines = []
    for (sam, pages, length), count in sorted(sizes.items()):
        within = "yes" if pages <= PAGE_LIMIT and length <= LENGTH_LIMIT else "NO"
        lines.append(f"{sam} | {pages} pages | {length} octets | {count} messages | within limit: {within}")
    lines.append(f"incomplete: {incomplete}")

    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten to {OUTPUT.name}")


if __name__ == "__main__":
    main()
