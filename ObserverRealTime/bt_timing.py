#!/usr/bin/env python3
# =============================================================================
#  bt_timing.py - bench measurement of the Bluetooth Legacy transport
#
#  Reads a sniffer capture (DRIP_Sniffer.ino in `radio bt` mode, "Format BT")
#  and reports, per advertiser address, the numbers needed to confirm the
#  transmitter's timing constants (DRIP_BLE_ADV_INT_UNITS, DRIP_BLE_ADV_SLOT_MS,
#  DRIP_BLE_FLEET_MAX). COMMANDS.md section 1.7 is the procedure.
#
#  This is a MEASUREMENT tool, not a conformance checker. It does not verify
#  signatures, hashes or the endorsement chain: that is observer.py's job. It
#  never raises an E-code. It only counts and times what arrived.
#
#  Usage:
#      python bt_timing.py capture.txt
#      python bt_timing.py capture.txt --skip 10           # ignore the first 10 s
#      python bt_timing.py capture.txt --addr C2:44:52:49:50:00
#
#  Standards the numbers are compared with:
#    ASTM F3411-22a 5.4.4.1 (BUR0010): Location/Vector at least every 1 s.
#    ASTM F3411-22a 5.4.4.1: static messages (Basic ID, System, Self ID,
#        Operator ID) at least every 3 s.
#    ASTM F3411-22a 5.4.4.2 (BUR0050/BUR0060): one Message Counter per message
#        type; all pages of one Authentication message share it. Gaps in a
#        type's counter are what this tool counts as lost messages.
#    RFC 9575 5: DRIP Single Page FEC recovers exactly one missing page.
#
#  Limits of the measurement, stated in the report too:
#    * Timestamps are taken by the sniffer's host stack, not the radio, so they
#      carry a few ms of jitter. Medians are sound; single values are not.
#    * One advertising event is sent on channels 37, 38 and 39, and a scanner
#      listens on one channel at a time, so it catches at most one copy per
#      event. The time between copies is therefore interval + advDelay
#      (0..10 ms, mean 5 ms), or a multiple of it when events are missed.
#    * A gap measured at the receiver includes the transmitter's schedule AND
#      reception losses. A Location gap over 1 s with zero Location loss is a
#      transmitter fault; with loss, it may be the radio path.
# =============================================================================
import argparse
import re
import statistics
import sys
from collections import defaultdict

META_RE = re.compile(
    r'^#B\s+addr=([0-9A-Fa-f:]{17})\s+rssi=(-?\d+)\s+t_ms=(\d+)\s+len=(\d+)'
    r'(?:\s+t_us=(\d+))?')
STATS_RE = re.compile(r'^#\s*stats\s+captured=(\d+)\s+dropped=(\d+)')

UUID_LO, UUID_HI, APP_CODE = 0xFA, 0xFF, 0x0D     # ASTM F3411-22a Table 14
SVC_HDR = 4                                        # UUID(2) + AppCode(1) + counter(1)
MSG_LEN = 25

TYPE_NAME = {0x0: "Basic ID", 0x1: "Location", 0x2: "Auth", 0x3: "Self ID",
             0x4: "System", 0x5: "Operator ID"}
SAM_NAME = {0x01: "Link", 0x02: "Wrapper", 0x03: "Manifest", 0x04: "Frame"}

# A message key seen again after this long is a NEW message whose 8-bit
# counter wrapped, not another copy of the old one.
NEW_INSTANCE_S = 10.0          # non-Auth: counters wrap after >= 128 s at 2/s
NEW_AUTH_INSTANCE_S = 20.0     # a Link's pages span ~8 s under one counter
EDGE_S = 10.0                  # Auth messages this close to the capture ends are "edge"


def parse(text):
    """Return (records, damaged, sniffer_dropped).
    record = dict(addr, rssi, t (seconds), counter, msg (25 bytes))."""
    records, damaged, dropped = [], 0, 0
    meta = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = META_RE.match(line)
        if m:
            meta = m
            continue
        s = STATS_RE.match(line)
        if s:
            dropped = max(dropped, int(s.group(2)))
            continue
        if line.startswith('#') or meta is None:
            continue
        hexs = re.sub(r'[^0-9A-Fa-f]', '', line)
        m, meta = meta, None
        try:
            svc = bytes.fromhex(hexs)
        except ValueError:
            damaged += 1
            continue
        if len(svc) != int(m.group(4)) or len(svc) < SVC_HDR + MSG_LEN:
            damaged += 1                                 # serial-side byte loss
            continue
        if svc[0] != UUID_LO or svc[1] != UUID_HI or svc[2] != APP_CODE:
            continue
        t_us = int(m.group(5)) if m.group(5) else int(m.group(3)) * 1000
        records.append({"addr": m.group(1).upper(), "rssi": int(m.group(2)),
                        "t": t_us / 1e6, "counter": svc[3],
                        "msg": svc[SVC_HDR:SVC_HDR + MSG_LEN]})
    return records, damaged, dropped


class Instance:
    """One transmitted message (or one Auth page), with all its received copies."""
    __slots__ = ("key", "first", "last", "times", "msg")

    def __init__(self, key, t, msg):
        self.key, self.first, self.last, self.times, self.msg = key, t, t, [t], msg


def build_instances(recs):
    """Group copies into instances. Key: (type, counter) for ordinary messages,
    (2, counter, page) for Authentication pages (BUR0060: one counter per page
    set, so the page number tells the pages apart)."""
    live, out = {}, []
    for r in recs:
        msg = r["msg"]
        mtype = msg[0] >> 4
        key = (mtype, r["counter"], msg[1] & 0x0F) if mtype == 0x2 else (mtype, r["counter"])
        inst = live.get(key)
        # Same key but different bytes, or long silence: a new message.
        if inst is None or inst.msg != msg or r["t"] - inst.last > NEW_INSTANCE_S:
            inst = Instance(key, r["t"], msg)
            live[key] = inst
            out.append(inst)
        else:
            inst.last = r["t"]
            inst.times.append(r["t"])
    return out


def counter_loss(instances):
    """Messages expected from the counter sequence vs messages received.
    Counters advance by 1 per new message (BUR0050), modulo 256."""
    if not instances:
        return 0, 0
    seq = [i.key[1] for i in sorted(instances, key=lambda i: i.first)]
    expected = 1
    for a, b in zip(seq, seq[1:]):
        d = (b - a) % 256
        expected += d if 1 <= d <= 127 else 1           # 0 or backwards: count as one
    return expected, len(seq)


def auth_messages(instances):
    """Group Auth pages into Authentication messages by counter (RFC 9575 5.2:
    the counter correlates pages on Legacy)."""
    groups = []
    live = {}
    for inst in sorted(instances, key=lambda i: i.first):
        c = inst.key[1]
        g = live.get(c)
        if g is None or inst.first - g["last"] > NEW_AUTH_INSTANCE_S:
            g = {"counter": c, "pages": {}, "first": inst.first, "last": inst.first}
            live[c] = g
            groups.append(g)
        g["pages"][inst.key[2]] = inst.msg
        g["last"] = max(g["last"], inst.last)
    return groups


def classify_auth(g):
    """complete | fec (exactly one page missing, recoverable by RFC 9575 5) |
    lost (two or more missing) | nopage0 (page 0 never arrived, so the Last
    Page Index and SAM type are unknown and the message cannot be classified)."""
    p0 = g["pages"].get(0)
    if p0 is None:
        return "nopage0", None, None
    lpi, length, sam = p0[2], p0[3], p0[8]
    missing = [p for p in range(lpi + 1) if p not in g["pages"]]
    # FEC present: LPI one page beyond what Length + ADL need (RFC 9575 5.2).
    data_pages = -(-(6 + length + 1) // 23)
    has_fec = (lpi + 1) == data_pages + 1
    if not missing:
        return "complete", sam, has_fec
    if len(missing) == 1 and has_fec:
        return "fec", sam, has_fec
    return "lost", sam, has_fec


def pct(n, d):
    return f"{100.0 * n / d:5.1f} %" if d else "  n/a"


def quantile(vals, q):
    s = sorted(vals)
    return s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))]


def report_addr(addr, recs, loc_limit, static_limit):
    t0, t1 = recs[0]["t"], recs[-1]["t"]
    dur = max(t1 - t0, 1e-9)
    insts = build_instances(recs)
    print(f"\n=== {addr}   {dur:.1f} s   {len(recs)} adverts received "
          f"({len(recs) / dur:.1f}/s)   RSSI median {statistics.median(r['rssi'] for r in recs)} dBm")

    # ---- real advertising interval: time between copies of one message ----
    deltas = []
    for i in insts:
        deltas += [(b - a) * 1000 for a, b in zip(i.times, i.times[1:])]
    if deltas:
        med = statistics.median(deltas)
        print(f"  time between copies  median {med:6.1f} ms   p10 {quantile(deltas, .1):6.1f}"
              f"   p90 {quantile(deltas, .9):6.1f}   min {min(deltas):6.1f}   (n={len(deltas)})")
        print(f"  -> real interval ~ {med - 5:.1f} ms (median minus the 5 ms mean advDelay)")
        print("     copies only exist while one message is on the air, so with a slot under")
        print("     about 2 intervals this is biased LOW. Measure the interval with a long")
        print("     slot ('radio slot 200' on the transmitter), then sweep the slot.")
    else:
        print("  time between copies  n/a (no message received twice)")
    copies = [len(i.times) for i in insts]
    one = sum(1 for c in copies if c == 1)
    print(f"  copies per message   mean {statistics.mean(copies):.2f}   "
          f"received only once {pct(one, len(copies))}")

    # ---- loss per ordinary message type, from counter gaps ----
    print("  message loss (from counter gaps, ASTM 5.4.4.2):")
    by_type = defaultdict(list)
    for i in insts:
        if i.key[0] != 0x2:
            by_type[i.key[0]].append(i)
    for mtype in sorted(by_type):
        exp, got = counter_loss(by_type[mtype])
        print(f"    {TYPE_NAME.get(mtype, hex(mtype)):<11} expected {exp:6d}  received {got:6d}"
              f"  lost {exp - got:5d}  ({pct(exp - got, exp)})   {got / dur:5.2f}/s")

    # ---- refresh gaps against ASTM 5.4.4.1 ----
    for mtype, limit, rule in ((0x1, loc_limit, "BUR0010 Location <= 1 s"),
                               (0x0, static_limit, "static Basic ID <= 3 s"),
                               (0x4, static_limit, "static System <= 3 s"),
                               (0x3, static_limit, "static Self ID <= 3 s"),
                               (0x5, static_limit, "static Operator ID <= 3 s")):
        firsts = sorted(i.first for i in by_type.get(mtype, []))
        if len(firsts) < 2:
            continue
        gaps = [b - a for a, b in zip(firsts, firsts[1:])]
        over = sum(1 for g in gaps if g > limit)
        print(f"  {rule:<26} max gap {max(gaps):5.2f} s   gaps over limit {over:4d}"
              f"   {'PASS' if over == 0 else 'FAIL'} (at the receiver)")

    # ---- Authentication messages ----
    auth_pages = [i for i in insts if i.key[0] == 0x2]
    groups = auth_messages(auth_pages)
    tally = defaultdict(lambda: defaultdict(int))
    for g in groups:
        edge = g["first"] - t0 < EDGE_S or t1 - g["last"] < EDGE_S
        status, sam, has_fec = classify_auth(g)
        name = SAM_NAME.get(sam, "unknown SAM") if sam is not None else "page 0 lost"
        tally[name]["edge" if edge and status != "complete" else status] += 1
        if status in ("complete", "fec", "lost") and has_fec is False:
            tally[name]["no FEC"] += 1
    if groups:
        print("  authentication messages (edge = cut by the capture start/end, not counted):")
        for name in sorted(tally):
            t = tally[name]
            n = t["complete"] + t["fec"] + t["lost"] + t["nopage0"]
            print(f"    {name:<13} complete {t['complete']:5d}  FEC-recoverable {t['fec']:4d}"
                  f"  lost {t['lost']:4d}  no page 0 {t['nopage0']:4d}  edge {t['edge']:3d}"
                  f"   usable {pct(t['complete'] + t['fec'], n)}"
                  + (f"   WITHOUT FEC {t['no FEC']}" if t["no FEC"] else ""))
    return len(recs) / dur


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bluetooth Legacy timing from a Format BT capture")
    ap.add_argument("capture")
    ap.add_argument("--skip", type=float, default=0.0,
                    help="ignore the first N seconds (warm-up, radio switch)")
    ap.add_argument("--addr", default=None, help="only this advertiser address")
    ap.add_argument("--loc-limit", type=float, default=1.0,
                    help="Location refresh limit in s (ASTM 5.4.4.1 BUR0010: 1.0)")
    ap.add_argument("--static-limit", type=float, default=3.0,
                    help="static message refresh limit in s (ASTM 5.4.4.1: 3.0)")
    a = ap.parse_args(argv)

    with open(a.capture, encoding="utf-8", errors="replace") as f:
        records, damaged, dropped = parse(f.read())
    if not records:
        print("No Format BT records ('#B addr=...') found. Was the sniffer in 'radio bt'?")
        return 1
    t_start = records[0]["t"] + a.skip
    records = [r for r in records if r["t"] >= t_start]
    if a.addr:
        records = [r for r in records if r["addr"] == a.addr.upper()]
    by_addr = defaultdict(list)
    for r in records:
        by_addr[r["addr"]].append(r)

    print(f"bt_timing: {a.capture}")
    print(f"  {len(records)} ODID adverts from {len(by_addr)} address(es); "
          f"damaged lines {damaged}; sniffer dropped {dropped}")
    if dropped:
        print("  WARNING: the sniffer dropped records (serial too slow). Loss figures "
              "below include them and are NOT radio losses.")
    total = 0.0
    for addr in sorted(by_addr):
        total += report_addr(addr, by_addr[addr], a.loc_limit, a.static_limit)
    print(f"\nall addresses: {total:.1f} adverts/s received")
    print("note: times come from the sniffer's host stack (a few ms jitter); "
          "gaps at the receiver include reception losses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
