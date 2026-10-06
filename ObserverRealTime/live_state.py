#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - live_state.py
#  The accumulating world model behind the real-time map.
#
#  It answers, at any instant: which drones am I detecting, where are they, and
#  what is wrong with what they are sending.
#
# -----------------------------------------------------------------------------
#  RELATIONSHIP TO observer.py  -- READ THIS FIRST
#
#  This module does NOT re-implement any validation. Every per-frame check is
#  performed by calling observer.process_payload(), the same function the batch
#  observer uses. What is different is only WHEN checks run, and that difference
#  is forced by the problem, not chosen:
#
#      batch : sees the whole capture, then judges.
#      live  : must judge with only what has arrived so far.
#
#  CONSEQUENCE, STATED PLAINLY: the live view and the batch report CAN DISAGREE.
#  A Manifest may reference a Message Pack that is re-transmitted a moment after
#  the Manifest itself (the firmware re-beacons each pack at ~10 Hz while its
#  content changes at ~3 Hz - see ed25519_backend.py). Batch matches it; live
#  may already have flagged it. The grace period below shrinks that window but
#  cannot close it.
#
#  THEREFORE: the live map is a MONITORING tool. The authoritative conformance
#  result is a batch observer.py run over the completed capture file. The web
#  page states this on its face so the screen is never mistaken for the report.
#
# -----------------------------------------------------------------------------
#  WHY MANIFEST VERIFICATION IS INCREMENTAL (RFC 9575 4.4)
#
#  observer.verify_manifests() is a BATCH function: on every call it re-decodes
#  every Manifest, re-hashes every Message Pack, and restarts the per-UA chain
#  cursor from empty. Calling it repeatedly on a growing capture fails twice:
#
#   1. DUPLICATE FINDINGS. It appends into `findings` each time, so one real
#      error would be counted once per pass - the count would measure how often
#      we re-checked, not how often it happened.
#
#   2. COST. _collect_pack_hashes() cSHAKE128-hashes EVERY pack seen so far, on
#      every call. MEASURED here: 1.537 ms per 296-byte pack.
#          1 min of capture  ->  2.8 s per call
#         10 min             -> 27.7 s per call
#         60 min             -> 166  s per call
#      Against a 1 Hz refresh, the scheme collapses within a minute.
#
#  So this module keeps the state alive between passes - pack hashes, link
#  hashes, the per-UA chain cursor, and the set of Manifests already judged -
#  and touches only what is new. Cost becomes flat per frame, and every finding
#  is raised exactly once.
#
#  observer.verify_manifests() ITSELF IS NOT MODIFIED. The batch report keeps
#  behaving exactly as it does today.
#
# -----------------------------------------------------------------------------
#  THE GRACE PERIOD AND THE WARM-UP  (both default 4 s)
#
#  GRACE: E-MAN-02 / E-MAN-03 ask "does this hash match something I have seen?"
#  A Manifest covers messages sent BEFORE it, but frames are lost and re-sent.
#  Judging a Manifest the instant it lands would raise false misses. Each
#  Manifest therefore waits `grace_s` before those two checks are decided.
#  E-MAN-01 (signature), E-MAN-05 (self-hash) and E-MAN-04 (chain) need no other
#  observation and are decided immediately.
#
#  WARM-UP: at start-up the pack-hash set is empty, so the first Manifests refer
#  to packs captured before we attached. E-MAN-02 / E-MAN-03 are therefore
#  suppressed for Manifests that ARRIVE within `warmup_s` of start.
#
#  This is not hypothetical. In the reference capture CaptureWithDNS4.txt the
#  batch observer reports E-MAN-02 on frame[0], frame[1] and frame[2] - the
#  first frame of each of the three drones - because those Manifests reference
#  packs sent before the capture began. That is the artefact this suppresses.
#
# -----------------------------------------------------------------------------
#  TIME
#  Staleness uses the HOST clock at the moment a frame was read. It does NOT use
#  the sniffer's timestamp: DRIP_Sniffer.ino states in its own banner that those
#  are microseconds since THAT BOARD booted, not wall clock, and the underlying
#  counter wraps every ~71.6 min. Point times on the map are still the DRIP VNB
#  (RFC 9575 3.2.4.3), exactly as make_map.py uses them.
# =============================================================================

import time
import threading
import ipaddress

import odid
import observer
import flight_tracks
import errors as drip_errors
from make_map import PALETTE, vnb_to_iso, identity_style

try:
    import det
    HAVE_DET = True
except ImportError:
    HAVE_DET = False


# Seconds between the Unix epoch and the DRIP/ODID epoch (2019-01-01).
# Same value as odid.EPOCH_2019; named here so the override maths is explicit.
DRIP_EPOCH = 1546300800

# How many "@ where -- detail" examples to keep per aggregated error code.
# The count is exact; the samples are only there to make a code actionable.
MAX_SAMPLES = 5


def _iso(t):
    if t is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


# ===========================================================================
#  RFC 9575 Appendix A - Authentication States (session 3, 2026-09-30)
#
#  Appendix A is INFORMATIVE (a MAY): a recommended way to show the Observer's
#  confidence in a claimed sender. Applied here per drone (per DET), cumulative
#  over the observation session ("up to that point").
#
#  Author decisions:
#    * Verified / Trusted additionally need RFC 9575 §6.4.2 (correlation with
#      another source, e.g. seeing the UA where it claims to be). The bench has
#      no such source, so the OPERATOR asserts it with the per-drone button
#      "Confirmed by observation" (POST /confirm). Until then a drone whose
#      signatures all pass stays Unverifiable (yellow), and says why.
#    * Trusted (A.6): the drone's key was put in the trust file by the owner, or
#      reached the Apex only through RAAs/HDAs listed in the trust file
#      (observer.trusted_registrar_dets, option A).
#
#  Evidence used:
#    success  - a Manifest or Wrapper signature that verified; an endorsement
#               (DRIP Link) of this DET that the chain walk accepted
#    failure  - FAIL_CODES below, signature/binding or content validation
#    pending  - a check waiting for a key; E-LINK-03 (chain still incomplete,
#               i.e. data MISSING, not data wrong - RFC 9575 A.4)
#    partial  - Authentication pages seen, message never completed
#    unsupported - Auth Type != 5, SAM Type not Link/Wrapper/Manifest, or a
#               Legacy Wrapper (RFC 9575 4.3.1 form not implemented)
#  Structural (E-FMT/E-PACK/E-AUTH/E-SEM) and capture (W-) codes are NOT
#  authentication evidence and never change the colour.
# ===========================================================================
FAIL_CODES = {
    # signature / binding
    "E-SIG-01", "E-MAN-01", "E-LINK-01", "E-LINK-02", "E-DET-02",
    # content validation
    "E-LINK-04", "E-MAN-03", "E-MAN-04", "E-MAN-05", "E-FEC-01", "E-FEC-02",
    "E-FRESH-01",
}
PENDING_LINK_CODES = {"E-LINK-03"}

# Timed evidence kept per drone for the state window (bounded memory).
MAX_EVENTS = 20000

# RFC 9575 Table 4 colour names, as clearly distinct screen colours.
AUTH_STATES = {
    "None":         "#111111",   # black
    "Partial":      "#9E9E9E",   # gray
    "Unsupported":  "#8B5A2B",   # brown
    "Unverifiable": "#F2C200",   # yellow
    "Verified":     "#1E9E3A",   # green
    "Trusted":      "#1F5FD6",   # blue
    "Questionable": "#F28C1E",   # orange
    "Unverified":   "#D62828",   # red
    "Conflicting":  "#7B2CBF",   # purple
}
AUTH_STATE_REF = {
    "None": "A.1", "Partial": "A.2", "Unsupported": "A.3", "Unverifiable": "A.4",
    "Verified": "A.5", "Trusted": "A.6", "Questionable": "A.7",
    "Unverified": "A.8", "Conflicting": "A.9",
}


def auth_state(ok, fail, pending, partial, unsupported, complete, confirmed,
               trusted):
    """The RFC 9575 Appendix A state of one claimed sender. Returns
       (state_name, reason). Pure function: every input is a count or a flag."""
    if fail and ok:
        if trusted:
            return "Conflicting", (f"{ok} verified and {fail} failed check(s); "
                                   "the key is trusted (A.9)")
        return "Questionable", f"{ok} verified and {fail} failed check(s) (A.7)"
    if fail:
        return "Unverified", f"{fail} failed check(s), none verified (A.8)"
    if ok:
        if not confirmed:
            return "Unverifiable", (f"{ok} check(s) verified, but RFC 9575 §6.4.2 "
                                    "correlation not confirmed - use 'Confirmed by "
                                    "observation'")
        if trusted:
            return "Trusted", (f"{ok} check(s) verified, §6.4.2 confirmed, key "
                               "trusted (A.6)")
        return "Verified", (f"{ok} check(s) verified, §6.4.2 confirmed; key not "
                            "under trusted registrars only (A.5)")
    if pending or complete:
        return "Unverifiable", ("complete Authentication received; key or chain "
                                "still missing (A.4)")
    if unsupported:
        return "Unsupported", (f"{unsupported} Authentication message(s) of a type "
                               "this Observer cannot verify (A.3)")
    if partial:
        return "Partial", "Authentication pages received, no complete message yet (A.2)"
    return "None", "no Authentication received yet (A.1)"


class Drone:
    """One claimed sender, keyed by its DRIP Entity Tag.

    Keyed on the DET and not the MAC, for the reason observer.collect_identities
    already documents: the DET *is* the identity (RFC 9374 3.5.2 binds it to a
    key), while ASTM F3411-22a 5.4.5.6 NOTE 2 explicitly permits a UA using
    Specific Session ID Type to rotate MAC addresses.
    """

    __slots__ = ("key", "det_bytes", "label", "color", "macs", "points",
                 "findings", "first_seen", "last_seen", "frames", "packs",
                 "_finding_order",
                 # RFC 9575 Appendix A evidence (session 3)
                 "dash", "auth_ok", "auth_complete", "auth_partial",
                 "auth_unsupported", "confirmed",
                 # state window = last complete endorsement cycle (session 3)
                 "events", "cycle_seen", "cycle_bounds", "cycles")

    def __init__(self, key, det_bytes, label, color):
        self.key = key
        self.det_bytes = det_bytes
        self.label = label
        self.color = color
        self.macs = set()
        self.points = []
        self.findings = {}          # error_id -> aggregate
        self._finding_order = []    # first-appearance order, for stable display
        self.first_seen = None
        self.last_seen = None
        self.frames = 0
        self.packs = 0
        self.dash = None
        self.auth_ok = 0            # verified signatures (Manifest / Wrapper)
        self.auth_complete = 0      # complete Authentication messages received
        self.auth_partial = 0       # incomplete / lost ones
        self.auth_unsupported = 0
        self.confirmed = False      # operator's RFC 9575 §6.4.2 confirmation
        # Timed evidence for the state WINDOW: (t, kind, error_id or None),
        # kind in ok / f (finding) / complete / partial / unsupported.
        self.events = []
        self.cycle_seen = set()     # chain edges received in the cycle in progress
        self.cycle_bounds = []      # completion times of the last two cycles
        self.cycles = 0             # complete endorsement cycles so far

    def ev(self, now, kind, eid=None):
        """Record one piece of timed evidence (also bumps the session counter)."""
        self.events.append((now, kind, eid))
        if len(self.events) > MAX_EVENTS:
            del self.events[:len(self.events) - MAX_EVENTS]
        if kind == "ok":
            self.auth_ok += 1
        elif kind == "complete":
            self.auth_complete += 1
        elif kind == "partial":
            self.auth_partial += 1
        elif kind == "unsupported":
            self.auth_unsupported += 1

    def window_start(self):
        """Start of the LAST COMPLETE endorsement cycle, or None while fewer
        than two cycle boundaries exist (then the window is the whole session,
        as RFC 9575 Appendix A describes)."""
        return self.cycle_bounds[-2] if len(self.cycle_bounds) >= 2 else None

    def note_finding(self, error_id, where, detail, now):
        agg = self.findings.get(error_id)
        if agg is None:
            desc, constraint = drip_errors.ERROR_CATALOG.get(
                error_id, ("(unknown error id)", ""))
            agg = {"count": 0, "first": now, "last": now,
                   "description": desc, "constraint": constraint,
                   "samples": []}
            self.findings[error_id] = agg
            self._finding_order.append(error_id)
        agg["count"] += 1
        agg["last"] = now
        self.ev(now, "f", error_id)
        if len(agg["samples"]) < MAX_SAMPLES:
            s = f"@ {where}"
            if detail:
                s += f"  -- {detail}"
            agg["samples"].append(s)

    def status(self, now, stale_s, drop_s):
        if self.last_seen is None:
            return "unknown"
        age = now - self.last_seen
        if age >= drop_s:
            return "dropped"
        if age >= stale_s:
            return "stale"
        return "live"


class LiveState:
    """Thread-safe accumulating state. ingest_*() from the reader thread,
       snapshot() from the HTTP thread."""

    def __init__(self, keys=None, stale_s=10.0, drop_s=90.0, grace_s=4.0,
                 warmup_s=4.0, trail=500, max_age=None, clock=time.time,
                 trusted_registrars=None):
        # `clock` is injectable ONLY so the replay harness can drive grace and
        # warm-up from the capture's own timeline instead of wall time. In
        # normal operation this is time.time() and staleness is host wall clock,
        # never the sniffer's boot-relative timestamp.
        self._clock = clock
        self.keys = keys
        # RFC 9575 A.6: DETs of the RAAs/HDAs the owner trusts as registrars
        # (observer.trusted_registrar_dets). Empty = nothing is ever Trusted.
        self.trusted_registrars = set(trusted_registrars or ())
        self.stale_s = stale_s
        self.drop_s = drop_s
        self.grace_s = grace_s
        self.warmup_s = warmup_s
        self.trail = trail
        self.max_age = max_age

        self.started = self._clock()
        self._warmup_until = self.started + warmup_s
        self._lock = threading.RLock()

        self.drones = {}            # det_str -> Drone
        self.unattributed = Drone("(unattributed)", None,
                                  "(unattributed - format/pack level)", "#808080")

        # ---- incremental manifest / link state (see module docstring) ----
        self._pack_hashes = set()       # cSHAKE128-8 of every observed pack
        self._link_hashes = set()       # cSHAKE128-8 of every observed Link SAM
        self._prev_by_det = {}          # DET bytes -> that UA's last Curr hash
        self._seen_manifests = set()    # sam_data bytes already judged
        self._pending = []              # Manifests awaiting the grace period
        self._bes = {}                  # unique DRIP Link BEs, by identity key
        self._bes_dirty = False
        # Evidence whose key has not arrived yet. Drained on every tick, after
        # the chain has been re-walked, and kept on the queue while it is still
        # keyless: live, "no key" is a state that a later endorsement can end,
        # so it is only reported once the queue stops shrinking.
        self._deferred = observer.DeferredChecks()
        # Current chain verdict, REPLACED wholesale on every recompute.
        # (drone_key_or_None, error_id) -> aggregate.  See _verify_links().
        self._link_verdict = {}

        # Global de-duplication of (error_id, where, detail). The Link chain is
        # re-verified whenever a new endorsement appears, which would otherwise
        # re-report the same finding about the same endorsement every time.
        self._reported = set()

        # flight_tracks re-use. Identity state is kept PER MAC rather than as a
        # single running value: with several drones interleaved on one channel a
        # single cursor could attribute one aircraft's Location to another.
        # (flight_tracks' own module docstring notes each Format A frame carries
        # its own Basic ID, so this is belt-and-braces, never worse.)
        self._tracks = {}
        self._ft_state_by_mac = {}
        self._track_seen = {}

        # ---- Bluetooth Legacy (session 3) --------------------------------
        # The batch judge's own context and functions (observer.
        # new_legacy_context / process_legacy_event), so live and batch agree.
        self._legacy = observer.new_legacy_context()
        self._msg_hashes = set()        # cSHAKE128-8 of single Legacy messages
        self._bt_det_by_addr = {}       # address -> last DET its Basic ID carried
        self._prev_t_by_det = {}        # DET -> (kind, t_us) of its last Manifest
        self.man_chain_gaps = 0         # Manifests not chain-compared (one lost between)
        self.bt_adverts = 0

        # ------------------------------------------------------------------
        #  TEST-ONLY VERIFICATION TIME OVERRIDE
        #
        #  None = use the real host clock (the only correct setting).
        #
        #  When set, this replaces the reference time used for TIME-BASED
        #  CHECKS ONLY - E-LINK-04 (RFC 9575 3.2.4.3 validity window) and
        #  E-FRESH-01. It exists because this bench's transmitter has no RTC,
        #  no GNSS and no NTP: drip_time.h builds every timestamp from a
        #  hardcoded SIM_DRIP_TIME_BASE, so the aircraft broadcasts a date that
        #  is months in the past and every window check fails for a reason that
        #  has nothing to do with conformance.
        #
        #  WHAT IT DOES NOT DO. It does not correct the aircraft. It makes the
        #  OBSERVER agree with a clock known to be wrong, which is the opposite
        #  of what a conformance tool should do. RFC 9575's validity window
        #  works precisely BECAUSE the Observer uses its own trusted time to
        #  reject stale or replayed endorsements; an Observer whose clock can be
        #  wound back will accept a replayed year-old endorsement. So any run
        #  with this set is a BENCH EXERCISE, never evidence.
        #
        #  It is therefore off by default, announced on the terminal, carried in
        #  every /state.json snapshot, and banner-flagged on the page so a
        #  screenshot can never be mistaken for a clean result.
        #
        #  STALENESS IS DELIBERATELY EXCLUDED. "Am I hearing this drone right
        #  now" is a question about the real world, so stale/drop and last-seen
        #  always use the real host clock even when this is set.
        # ------------------------------------------------------------------
        self.time_override = None

        self.frames_ok = 0
        self.frames_damaged = 0
        self.frames_skipped = 0     # frames dropped by an ingest exception
        self.sniffer_stats = {}
        self.last_frame_at = None
        self._color_n = 0

    # ------------------------------------------------- verification clock
    def verify_now(self, host_now):
        """Reference time for TIME-BASED checks only. See time_override."""
        return host_now if self.time_override is None else self.time_override

    def set_time_override(self, unix_or_none):
        """Set (or clear, with None) the test-only verification time."""
        with self._lock:
            self.time_override = (None if unix_or_none is None
                                  else float(unix_or_none))
            # Force the chain verdict to be recomputed against the new clock,
            # otherwise E-LINK-04 would not change until a new endorsement
            # happened to arrive.
            self._bes_dirty = True
        return self.time_override

    # ---------------------------------------------------------------- drones
    def _drone_for(self, det_bytes):
        key = str(ipaddress.IPv6Address(bytes(det_bytes)))
        d = self.drones.get(key)
        if d is None:
            color, dash = identity_style(self._color_n)   # never an RFC state hue
            d = Drone(key, bytes(det_bytes), key, color)
            d.dash = dash
            self._color_n += 1
            self.drones[key] = d
        return d

    def _record(self, det_bytes):
        return self.unattributed if det_bytes is None else self._drone_for(det_bytes)

    def _report(self, det_bytes, error_id, where, detail, now):
        """Record one finding, de-duplicated on (id, where, detail)."""
        sig = (error_id, where, detail)
        if sig in self._reported:
            return
        self._reported.add(sig)
        self._record(det_bytes).note_finding(error_id, where, detail, now)

    # ---------------------------------------------------------------- ingest
    def ingest_damaged(self, meta, got, now=None):
        """A frame whose byte count contradicted the sniffer's declared length.

        W-CAP-01. It is capture-pipeline damage, NOT a DRIP or ASTM defect, and
        it says nothing about the drone that sent it - so it is deliberately
        attributed to nobody rather than blamed on an aircraft.
        """
        now = now or self._clock()
        with self._lock:
            self.frames_damaged += 1
            self._report(None, "W-CAP-01", f"capture@{self.frames_damaged}",
                         f"declared len={meta.get('len')}, got {got} B", now)

    def ingest_stats(self, stats):
        with self._lock:
            self.sniffer_stats = dict(stats)

    def ingest_frame(self, meta, frame, now=None):
        """Decode and validate one intact 802.11 frame."""
        now = now or self._clock()
        ie = odid.extract_drip_ie(frame)
        if ie is None:
            return                      # not an Open Drone ID beacon
        hdr = odid.parse_mac_header(frame)
        mac = odid.mac_str(hdr["addr2"]) if hdr else "??:??:??:??:??:??"

        with self._lock:
            self.frames_ok += 1
            self.last_frame_at = now
            idx = self.frames_ok
            where = f"frame[{idx}] {mac} cnt=0x{ie['counter']:02X}"

            # ---- per-frame validation: observer's OWN function, unmodified --
            findings = []
            items = []
            # `now` (real host clock) timestamps the findings and drives
            # staleness. self.verify_now(now) is what TIME-BASED checks compare
            # against, and is the only thing the test override can move.
            observer.process_payload(ie["payload"], where, self.keys,
                                     findings, items,
                                     now=self.verify_now(now),
                                     max_age=self.max_age, mac=mac,
                                     deferred=self._deferred)

            det_bytes = self._identity_of(items)
            drone = None
            if det_bytes is not None:
                drone = self._drone_for(det_bytes)
                drone.macs.add(mac)
                drone.frames += 1
                if drone.first_seen is None:
                    drone.first_seen = now
                drone.last_seen = now

            for f in findings:
                self._report(det_bytes, f.error_id, f.where, f.detail, now)

            self._count_wrapper_successes(items, findings, now)
            self._absorb(items, det_bytes, mac, where, now)

    def _count_wrapper_successes(self, items, findings, now):
        """A Wrapper checked NOW (key known) that raised no E-SIG-01 is a
        verified signature (RFC 9575 A.5 evidence). One checked later is
        counted in _drain_deferred."""
        if self.keys is None or not observer.HAVE_ED:
            return
        failed = {f.where for f in findings if f.error_id == "E-SIG-01"}
        for w, d in items:
            a = d.get("_auth")
            if (not a or a.get("auth_type") != 5 or a.get("sam_type") != 0x02
                    or a.get("legacy") or not a.get("complete")):
                continue
            sam = a.get("sam_data", b"")
            if len(sam) < 88:
                continue
            det_w = bytes(sam[8:24])
            if self.keys.for_det(det_w) is not None and w not in failed:
                self._drone_for(det_w).ev(now, "ok")

    def ingest_bt(self, rec, now=None):
        """One Bluetooth Legacy advertisement (Format BT). Session 3.

        Reassembly and judgement are observer.py's (process_legacy_event); this
        only routes the result into the live model. A Location carries no
        identity (ASTM Table 6), so a message is attributed to the DET last
        announced by a Basic ID from the SAME address."""
        now = now or self._clock()
        with self._lock:
            self.bt_adverts += 1
            self._legacy["health"]["records"] += 1
            self.last_frame_at = now
            for ev in self._legacy["asm"].feed(rec):
                findings, items = [], []
                observer.process_legacy_event(ev, self._legacy, self.keys, findings,
                                              items, now=self.verify_now(now),
                                              max_age=self.max_age,
                                              deferred=self._deferred)
                addr = ev[1]["addr"]
                det_bytes = self._identity_of(items)
                if det_bytes is not None:
                    self._bt_det_by_addr[addr] = det_bytes
                else:
                    det_bytes = self._bt_det_by_addr.get(addr)
                if det_bytes is not None:
                    drone = self._drone_for(det_bytes)
                    drone.macs.add(addr)
                    drone.frames += 1
                    if drone.first_seen is None:
                        drone.first_seen = now
                    drone.last_seen = now
                for f in findings:
                    self._report(det_bytes, f.error_id, f.where, f.detail, now)
                # RFC 9575 A.2: pages received, message never completed.
                if (ev[0] == "auth" and ev[1]["status"] in ("lost", "no_page0")
                        and det_bytes is not None):
                    self._drone_for(det_bytes).ev(now, "partial")
                self._count_wrapper_successes(items, findings, now)
                where = items[0][0] if items else f"bt {addr}"
                self._absorb(items, det_bytes, addr, where, now)

    def _identity_of(self, items):
        """The DET claimed in this frame's Basic ID (ASTM Table 6 has no
           identity field on Location, so identity comes from Basic ID)."""
        for _w, d in items:
            if d.get("type") == 0x0 and d.get("det") is not None:
                return bytes(d["det"])
        return None

    # -------------------------------------------------- accumulate the model
    def _absorb(self, items, det_bytes, mac, where, now):
        decoded = []
        for _w, d in items:
            if "_legacy_raw" in d:                      # session 3, RFC 9575 4.4.3.1
                if HAVE_DET:
                    self._msg_hashes.add(observer._man_hash8(d["_legacy_raw"]))
                continue
            if "_pack_raw" in d:
                if det_bytes is not None:
                    self._drone_for(det_bytes).packs += 1
                if HAVE_DET:
                    self._pack_hashes.add(observer._man_hash8(d["_pack_raw"]))
                continue
            if "_auth" in d:
                self._absorb_auth(d["_auth"], det_bytes, where, now)
                continue
            decoded.append(d)

        if decoded:
            self._absorb_points(decoded, det_bytes, mac, where, now)

    def _absorb_auth(self, auth, det_bytes, where, now):
        # ---- RFC 9575 Appendix A evidence (session 3) ----------------------
        if det_bytes is not None:
            dr = self._drone_for(det_bytes)
            if not auth.get("complete"):
                dr.ev(now, "partial")
            else:
                dr.ev(now, "complete")
                if (auth.get("auth_type") != 5
                        or auth.get("sam_type") not in (0x01, 0x02, 0x03)
                        or (auth.get("sam_type") == 0x02 and auth.get("legacy"))):
                    dr.ev(now, "unsupported")
        if auth.get("auth_type") != 5:
            return
        sam_type = auth.get("sam_type")
        sam = auth.get("sam_data", b"")

        # ---- DRIP Link (RFC 9575 4.2) -----------------------------------
        if sam_type == 0x01:
            if HAVE_DET:
                self._link_hashes.add(observer._man_hash8(bytes([0x01]) + bytes(sam)))
            be = odid.decode_link_sam(sam)
            if be is not None:
                k = be["det_child"] + be["det_parent"] + be["sig"]
                if k not in self._bes:
                    self._bes[k] = be
                    self._bes_dirty = True
                self._note_link_rx(be, now)
            return

        # ---- DRIP Manifest (RFC 9575 4.4) --------------------------------
        if sam_type == 0x03:
            if not HAVE_DET:
                return
            key = bytes(sam)
            if key in self._seen_manifests:
                return                      # same dedup rule as _collect_manifests
            self._seen_manifests.add(key)
            m = odid.decode_manifest_sam(sam)
            if m is None:
                return
            w = f"{where} manifest"
            m_det = m.get("det")

            # --- decided NOW: they need no other observation ---------------
            # E-MAN-01: UA signature over VNB|VNA|Evidence|DET
            if self.keys is not None and observer.HAVE_ED:
                pub = self.keys.for_det(m_det)
                if pub is None:
                    # The endorsement that carries this UA's key may still be
                    # in flight, so the check waits rather than accusing.
                    self._deferred.defer("manifest", m_det, w,
                                         (m["signed_region"], m["sig"]))
                elif not observer.ed25519_backend.verify(pub, m["signed_region"],
                                                         m["sig"]):
                    self._report(m_det or det_bytes, "E-MAN-01", w, "", now)
                elif m_det:
                    self._drone_for(m_det).ev(now, "ok")    # verified (A.5 evidence)

            # E-MAN-05: self-hash = cSHAKE128(Prev | null | Link | ASTM)
            calc = observer._man_hash8(m["prev"] + b"\x00" * 8 + m["link_hash"] +
                                       b"".join(m["astm_hashes"]))
            if calc != m["curr"]:
                self._report(m_det or det_bytes, "E-MAN-05", w,
                             f"curr={m['curr'].hex()} calc={calc.hex()}", now)

            # E-MAN-04: the per-UA ledger chain (RFC 9575 4.4.2).
            # Per UA, never global: observer.py documents that a single global
            # cursor reports a break on essentially every Manifest once more
            # than one aircraft is on the air.
            # Compared only between CONSECUTIVE Manifests of the UA - Legacy by
            # sniffer time, Wi-Fi by arrival time - with the rule batch uses
            # (observer.manifest_pair_comparable). A lost Manifest is a gap,
            # counted, not an E-MAN-04 (session 3, author decision).
            legacy = bool(auth.get("legacy"))
            kind = "bt" if legacy else "wifi"
            t_us = auth.get("t_us") if legacy else int(now * 1_000_000)
            prev_curr = self._prev_by_det.get(m_det)
            prev_kind, prev_t = self._prev_t_by_det.get(m_det, (None, None))
            comparable = observer.manifest_pair_comparable(kind, t_us, prev_kind, prev_t)
            if prev_curr is not None and m["prev"] != prev_curr:
                if comparable:
                    self._report(m_det or det_bytes, "E-MAN-04", w,
                                 f"prev={m['prev'].hex()} expected={prev_curr.hex()}",
                                 now)
                else:
                    self.man_chain_gaps += 1
            self._prev_by_det[m_det] = m["curr"]
            self._prev_t_by_det[m_det] = (kind, t_us)

            # --- deferred: they depend on what else has been observed -------
            # Bluetooth Legacy: the referenced Link can take tens of seconds
            # to arrive one page per second, and RFC 9575 §6.3 allows up to a
            # minute, so a Legacy Manifest waits observer.LEGACY_LINK_WAIT_S
            # (60 s) before E-MAN-02/03 are judged. Wi-Fi keeps --grace.
            wait = (max(self.grace_s, observer.LEGACY_LINK_WAIT_S)
                    if auth.get("legacy") else self.grace_s)
            self._pending.append({"due": now + wait, "arrived": now,
                                  "w": w, "m": m, "det": m_det or det_bytes,
                                  "legacy": legacy})

    def _absorb_points(self, decoded, det_bytes, mac, where, now):
        """Extract Location points by calling flight_tracks, so the position
           logic is shared with make_map.py and cannot drift."""
        st = self._ft_state_by_mac.setdefault(mac, flight_tracks.new_state())
        flight_tracks.process_decoded(decoded, where, self._tracks, st)

        for k, t in self._tracks.items():
            seen = self._track_seen.get(k, 0)
            if len(t["points"]) <= seen:
                continue
            new_pts = t["points"][seen:]
            self._track_seen[k] = len(t["points"])
            target = self._record(det_bytes) if det_bytes is not None else None
            if target is None:
                continue
            for p in new_pts:
                if p["lat"] is None or p["lon"] is None:
                    continue
                target.points.append({
                    "lat": p["lat"], "lon": p["lon"], "alt_m": p["alt_m"],
                    "speed_mps": p["speed_mps"], "heading_deg": p["heading_deg"],
                    "time": vnb_to_iso(p["vnb"]), "where": p["where"],
                    "host_t": now,
                })
            # Trail cap: the live view keeps a rolling window. The FULL track is
            # always still in the capture file for make_map.py.
            if self.trail and len(target.points) > self.trail:
                del target.points[:len(target.points) - self.trail]

            # MEMORY: flight_tracks keeps its OWN copy of every point and never
            # trims it, so before this each point was stored twice with one copy
            # growing without bound. Measured in a soak run: 13,859 frames gave
            # tracks_pts=13,859 against drone_pts=1,500. Trim it to the same cap.
            # _track_seen is an absolute index, so it is rebased by the same
            # amount or the next diff would replay old points.
            if self.trail and len(t["points"]) > self.trail:
                cut = len(t["points"]) - self.trail
                del t["points"][:cut]
                self._track_seen[k] = len(t["points"])

    # ------------------------------------------------------------------ tick
    def tick(self, now=None):
        """Resolve deferred checks. Called ~1 Hz by the observer loop."""
        now = now or self._clock()
        with self._lock:
            self._resolve_pending(now)
            if self._bes_dirty:
                # Unix seconds: observer.verify_link_chain() converts to the
                # DRIP epoch itself now that its units bug is fixed.
                self._verify_links(self.verify_now(now))
                self._bes_dirty = False
            self._drain_deferred(now)

    def _drain_deferred(self, now):
        """Run the evidence checks whose key the chain walk has since supplied.

        Entries that are still keyless stay on the queue rather than becoming
        E-KEY-01, which is the live counterpart of the batch rule that arrival
        order must not decide the verdict. The batch report over the finished
        capture is where a permanently keyless DET is named.
        """
        bucket = []
        before = [(k, d, w) for k, d, w, _p in self._deferred.items]
        failed = set()

        def sink(d, f):
            failed.add(f.where)
            self._report(d, f.error_id, f.where, f.detail, now)

        self._deferred.drain(self.keys, bucket, sink=sink, keep_keyless=True)
        # RFC 9575 A.5 evidence: a deferred signature check that ran (it left
        # the queue) and raised nothing has verified.
        still = {(k, d, w) for k, d, w, _p in self._deferred.items}
        for k, d, w in before:
            if (k, d, w) not in still and k in ("manifest", "wrapper") and w not in failed:
                self._drone_for(d).ev(now, "ok")

    def _resolve_pending(self, now):
        still = []
        for p in self._pending:
            if p["due"] > now:
                still.append(p)
                continue
            # WARM-UP: a Manifest that landed before the pack-hash set had a
            # chance to fill refers to packs captured before we attached. Not a
            # defect - see the module docstring.
            if p["arrived"] < self._warmup_until:
                continue
            m, w, d = p["m"], p["w"], p["det"]
            legacy = p.get("legacy", False)
            for h in m["astm_hashes"]:
                if h in self._pack_hashes or h in self._msg_hashes:
                    continue
                # Legacy: a message not received is not a finding (RFC 9575 4.4);
                # same rule as observer.verify_manifests.
                if not legacy:
                    self._report(d, "E-MAN-02", w,
                                 f"unmatched pack hash {h.hex()}", now)
            if m["link_hash"] not in self._link_hashes:
                if not (legacy and not self._link_hashes):
                    self._report(d, "E-MAN-03", w,
                                 f"unmatched link hash {m['link_hash'].hex()}", now)
        self._pending = still

    def _verify_links(self, now):
        """Re-verify the endorsement chain when a NEW endorsement appears.

        observer.verify_link_chain() performs the anchored traversal described
        in its own docstring; nothing about the chain logic lives here.

        WHY THIS IS A REPLACEABLE VERDICT AND NOT AN ACCUMULATING COUNT
        --------------------------------------------------------------
        The chain is assembled from endorsements that arrive separately and in
        no guaranteed order. A child endorsement received before its parent has
        no resolvable parent yet, so verify_link_chain() correctly reports
        E-LINK-03 ("no path to the trust anchor") - and then the parent arrives
        a moment later and the chain is fine.

        That is not an error that HAPPENED; it is a state that WAS true while
        the chain was still being collected. RFC 9575 9.1 says as much: the
        Observer must collect a complete chain of Link messages, and collection
        takes time.

        Counting those transients would be meaningless, and letting them stick
        would permanently show a broken chain on a healthy fleet. So the whole
        link verdict is recomputed and REPLACED on every change. Only the
        first-seen time is carried forward for verdicts that persist, so a
        genuinely broken chain still shows how long it has been broken.
        """
        bucket = []
        # The keyring is passed so the live path learns keys from the air on the
        # same terms as the batch path: the traversal descends from the anchors
        # the operator loaded, and every key it admits is recorded with the
        # endorsing parent. Without it the live observer would keep reporting
        # E-KEY-01 for an aircraft whose chain it had just verified.
        observer.verify_link_chain(self._current_bes(), bucket, now=now,
                                   keys=self.keys)

        new = {}
        for f in bucket:
            slot = new.setdefault((self._link_owner(f.where), f.error_id),
                                  {"count": 0, "samples": [], "first": None,
                                   "last": now})
            slot["count"] += 1
            if len(slot["samples"]) < MAX_SAMPLES:
                s = f"@ {f.where}"
                if f.detail:
                    s += f"  -- {f.detail}"
                slot["samples"].append(s)

        for k, v in new.items():
            old = self._link_verdict.get(k)
            v["first"] = old["first"] if old else now
        self._link_verdict = new

    def _current_bes(self):
        """The endorsements the live verdict judges: for each (child, parent)
        pair, only the NEWEST one - the latest VNB (session 3, 2026-10-04,
        author request).

        WHY. A transmitter re-signs an endorsement when it renews it, for
        example after its clock is set (`time <unix>`): the old copy stops being
        broadcast and the new one replaces it (RFC 9575 §3.2.4.3 gives each copy
        its own VNB..VNA). This view keeps every endorsement of the session, so
        without this rule a renewed pair kept failing E-LINK-04 forever on the
        copy that is no longer in use, and the drone could never look healthy
        again without restarting the observer.

        WHAT IS KEPT. Every endorsement sharing the latest VNB of its pair is
        judged, not just one: two different signatures with the same VNB are
        not a renewal, and neither may hide the other. A forged copy with a
        later VNB does supersede the genuine one here, but it is then the one
        judged, and it fails E-LINK-02 visibly - the attack cannot be silent.

        The batch report (observer.py) is unchanged: it is a record of what was
        broadcast, so every endorsement in the capture is still judged there."""
        newest = {}
        for be in self._bes.values():
            pair = (bytes(be["det_child"]), bytes(be["det_parent"]))
            cur = newest.get(pair)
            if cur is None or be["vnb"] > cur[0]:
                newest[pair] = (be["vnb"], [be])
            elif be["vnb"] == cur[0]:
                cur[1].append(be)
        return [be for _vnb, lst in newest.values() for be in lst]

    @staticmethod
    def _link_owner(where):
        """Map a Link finding to the drone it is about.

        verify_link_chain() labels every finding
            'Link BE child=<IPv6 DET>'
        so the child DET in that label is the owning identity. An endorsement
        for an HDA or RAA (not a UA on the air) matches no drone and lands in
        the unattributed bucket, which is correct: it is a statement about the
        registry chain, not about an aircraft.
        """
        if "child=" not in where:
            return None
        return where.split("child=", 1)[1].split()[0].strip()

    # ------------------------------------------- RFC 9575 Appendix A states
    def confirm(self, drone_key, confirmed=True):
        """Record the operator's RFC 9575 §6.4.2 confirmation for one drone:
        "I correlated this drone's claims with another source". In memory only,
        for this observation session, as §6.4.2 asks. Returns False if the
        drone is unknown."""
        with self._lock:
            d = self.drones.get(drone_key)
            if d is None:
                return False
            d.confirmed = bool(confirmed)
            return True

    def _key_trusted(self, det_bytes):
        """RFC 9575 A.6 with option A: the key is in the trust file, or every
        DIME that endorsed it, up to a trust-file entry, is a listed RAA/HDA."""
        if self.keys is None or det_bytes is None:
            return False
        origin = self.keys.origin(det_bytes)
        seen = set()
        while origin is not None and det_bytes not in seen:
            seen.add(det_bytes)
            if origin.source == observer.SRC_TRUST_FILE:
                return True
            if origin.source != observer.SRC_AIR or origin.parent_det is None:
                return False                    # CLI, registry, wildcard
            parent = origin.parent_det
            if parent not in self.trusted_registrars:
                return False
            det_bytes, origin = parent, self.keys.origin(parent)
        return False

    # ------------------------------------------- the state window (session 3)
    #  Author decision 2026-10-04: the colour reflects the drone's CURRENT
    #  state, judged on the last complete endorsement cycle - the period in
    #  which every link of its chain (UA <- HDA <- RAA <- Apex) was received at
    #  least once - plus the cycle in progress. Older evidence stays in the
    #  findings history but no longer moves the colour. This deliberately
    #  departs from RFC 9575 Appendix A's cumulative "up to that point" (the
    #  appendix is informative); one lost beacon an hour ago no longer marks a
    #  healthy drone for the rest of the session.
    def _chain_path(self, det_bytes):
        """Edges (child, parent) from this UA up to the Apex, from the newest
        endorsements received; None if the path is not complete yet."""
        by_child = {}
        for be in self._current_bes():
            by_child.setdefault(bytes(be["det_child"]), bytes(be["det_parent"]))
        path, cur, apex = [], bytes(det_bytes), bytes(observer.APEX_DET)
        for _ in range(8):
            parent = by_child.get(cur)
            if parent is None:
                return None
            path.append((cur, parent))
            if parent == apex:
                return path
            cur = parent
        return None

    def _note_link_rx(self, be, now):
        """One endorsement RECEIVED (every copy counts, not only new ones):
        advance the cycle of every drone whose chain contains it."""
        edge = (bytes(be["det_child"]), bytes(be["det_parent"]))
        for d in self.drones.values():
            if d.det_bytes is None:
                continue
            path = self._chain_path(d.det_bytes)
            if not path or edge not in path:
                continue
            d.cycle_seen.add(edge)
            if set(path) <= d.cycle_seen:
                d.cycles += 1
                d.cycle_bounds = (d.cycle_bounds + [now])[-2:]
                d.cycle_seen = set()
                ws = d.window_start()
                if ws is not None:                      # forget what can no longer count
                    d.events = [e for e in d.events if e[0] >= ws]

    @staticmethod
    def _in_window(d, kind, eid=None):
        ws = d.window_start()
        return sum(1 for t, k, e in d.events
                   if k == kind and (eid is None or e == eid)
                   and (ws is None or t >= ws))

    def _auth_state_of(self, d, now=None):
        now = now if now is not None else self._clock()
        ws = d.window_start()
        fail = sum(1 for t, k, e in d.events
                   if k == "f" and e in FAIL_CODES and (ws is None or t >= ws))
        pending = 0
        for (owner, eid), v in self._link_verdict.items():
            if owner != d.key:
                continue
            if eid in FAIL_CODES:
                fail += v["count"]
            elif eid in PENDING_LINK_CODES:
                pending += v["count"]
        ok = self._in_window(d, "ok")
        # An accepted endorsement of this DET is a verified Authentication
        # message too (the parent's signature over the child's key).
        if d.det_bytes is not None and not any(
                o == d.key and e in FAIL_CODES | PENDING_LINK_CODES
                for (o, e) in self._link_verdict):
            ok += sum(1 for be in self._bes.values() if be["det_child"] == d.det_bytes)
        if d.det_bytes is not None:
            pending += sum(1 for it in self._deferred.items if it[1] == d.det_bytes)
        trusted = self._key_trusted(d.det_bytes)
        name, reason = auth_state(ok, fail, pending, self._in_window(d, "partial"),
                                  self._in_window(d, "unsupported"),
                                  self._in_window(d, "complete"),
                                  d.confirmed, trusted)
        if ws is None:
            win = (f"window: whole session (no complete endorsement cycle yet)"
                   if d.cycles == 0 else
                   f"window: whole session (1 endorsement cycle complete, need 2)")
        else:
            win = (f"window: last complete endorsement cycle, started "
                   f"{max(0.0, now - ws):.0f} s ago ({d.cycles} cycles so far)")
        return {"name": name, "color": AUTH_STATES[name],
                "ref": "RFC 9575 Appendix " + AUTH_STATE_REF[name],
                "reason": reason + "; " + win, "confirmed": d.confirmed,
                "key_trusted": trusted, "cycles": d.cycles,
                "window_start": _iso(ws) if ws is not None else None}

    # -------------------------------------------------------------- snapshot
    def snapshot(self):
        """A JSON-serialisable picture of the world right now."""
        now = self._clock()
        with self._lock:
            drones = []
            for d in self.drones.values():
                status = d.status(now, self.stale_s, self.drop_s)
                if status == "dropped":
                    continue            # no longer "currently detecting"
                drones.append(self._drone_json(d, now, status))

            unattr = None
            if self.unattributed.findings:
                unattr = self._drone_json(self.unattributed, now, "n/a")

            warm = max(0.0, self._warmup_until - now)
            return {
                "now": _iso(now),
                "uptime_s": round(now - self.started, 1),
                "warmup_remaining_s": round(warm, 1),
                "drones": drones,
                "unattributed": unattr,
                # Always present, so a snapshot can never hide that a run was
                # done on a doctored clock.
                "time_override": (None if self.time_override is None else {
                    "unix": self.time_override,
                    "iso": _iso(self.time_override),
                    "drip_epoch_s": int(self.time_override - DRIP_EPOCH),
                }),
                "capture": {
                    "frames_ok": self.frames_ok,
                    "frames_damaged": self.frames_damaged,
                    "frames_skipped": self.frames_skipped,
                    "last_frame_age_s": (round(max(0.0, now - self.last_frame_at), 1)
                                         if self.last_frame_at else None),
                    "sniffer": self.sniffer_stats,
                    "bt": dict(self._legacy["health"], adverts=self.bt_adverts),
                    "man_chain_gaps": self.man_chain_gaps,
                },
                "config": {
                    "stale_s": self.stale_s, "drop_s": self.drop_s,
                    "grace_s": self.grace_s, "warmup_s": self.warmup_s,
                    "trail": self.trail,
                    "keys_loaded": (len(self.keys) if self.keys is not None else 0),
                    "trusted_registrars": len(self.trusted_registrars),
                },
                # RFC 9575 Appendix A, Table 4: the legend, from the same table
                # the states are computed from (one source).
                "auth_states": [{"name": n, "color": c,
                                 "ref": "RFC 9575 Appendix " + AUTH_STATE_REF[n]}
                                for n, c in AUTH_STATES.items()],
            }

    def _link_findings_for(self, drone_key):
        """Current chain verdict entries belonging to this drone (or to nobody,
           when drone_key is None)."""
        out = []
        for (owner, eid), v in self._link_verdict.items():
            if owner != drone_key:
                continue
            desc, constraint = drip_errors.ERROR_CATALOG.get(
                eid, ("(unknown error id)", ""))
            out.append({"id": eid, "count": v["count"],
                        "description": desc, "constraint": constraint,
                        "first": _iso(v["first"]), "last": _iso(v["last"]),
                        "samples": v["samples"],
                        # the chain verdict is recomputed, so always current
                        "window_count": v["count"]})
        return out

    def _drone_json(self, d, now, status):
        return {
            "key": d.key,
            "label": d.label,
            "color": d.color,
            "dash": d.dash,
            "auth_state": self._auth_state_of(d, now),
            "status": status,
            "macs": sorted(d.macs),
            "frames": d.frames,
            "packs": d.packs,
            "first_seen": _iso(d.first_seen),
            "last_seen": _iso(d.last_seen),
            "age_s": (round(max(0.0, now - d.last_seen), 1) if d.last_seen else None),
            "key_known": (self.keys is not None and d.det_bytes is not None
                          and self.keys.for_det(d.det_bytes) is not None),
            "points": d.points,
            "findings": [
                {
                    "id": eid,
                    "count": d.findings[eid]["count"],
                    "description": d.findings[eid]["description"],
                    "constraint": d.findings[eid]["constraint"],
                    "first": _iso(d.findings[eid]["first"]),
                    "last": _iso(d.findings[eid]["last"]),
                    "samples": d.findings[eid]["samples"],
                    # occurrences inside the state window (session 3)
                    "window_count": self._in_window(d, "f", eid),
                }
                for eid in d._finding_order
            ] + self._link_findings_for(d.det_bytes and d.key or None),
        }
