#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - observer.py
#  Reads a DRIP capture (Format W = Wireshark bytes-only export, or
#  Format B = flat hex), decodes it via odid.py, validates it against the
#  errors.py catalog, and prints a report.
#
#  Usage:
#     python3 observer.py <file.txt> [--pubkey HEX] [--keyring FILE]
#                                    [--verbose] [--now UNIX] [--max-age SEC]
#
#  --pubkey HEX : 32-byte Ed25519 public key (hex). Enables the DET<->key
#                 binding check (E-DET-02) for DRIP Basic ID messages.
#  --now / --max-age : enable freshness check (E-FRESH-01) against a reference time.
#
#  SESSION 3 (2026-09-29): Bluetooth Legacy captures (Format BT, ASTM F3411-22a
#  5.4.6) are decoded too, alone or mixed with Wi-Fi Format A. See the block
#  "Bluetooth Legacy" above verify_link_chain() for what is and is not judged.
# =============================================================================

import sys
import argparse
import ipaddress
from collections import Counter, defaultdict

import odid
from errors import Finding, ERROR_CATALOG

# det.py provides verify_det_binding() (RFC 9374 DET derivation). Optional:
try:
    import det
    HAVE_DET = True
except Exception:
    HAVE_DET = False

# ed25519.py provides RFC 8032 verify() for the Wrapper signature check. Optional:
try:
    import ed25519
    # The backend keeps ed25519.py as the normative reference and only uses a
    # faster implementation after proving it agrees (RFC 8032 §7.1 TEST 1,
    # valid AND tampered). It also memoises: the ~10 Hz beacon repeat
    # (ASTM §5.4.4.2 BUR0050) re-sends identical packs, and verifying an
    # identical (key,msg,sig) triple again cannot change the answer.
    import ed25519_backend
    HAVE_ED = True
except Exception:
    HAVE_ED = False

# Valid ODID authentication timestamp range, in seconds since 2019-01-01.
#
# ASTM F3411-22a Table 8 describes the field as a 32-bit Unix timestamp and
# states its limitation as 01/01/2019 to 01/19/2087. Those two dates are 2^31-1
# seconds apart (2019-01-01T00:00:00Z + 2147483647 s = 2087-01-19T03:14:07Z), so
# the printed limitation bounds the field to a SIGNED 32-bit range even though
# the field itself is 32 bits wide. The upper bound below is that limitation.
#
# An earlier value of 2**32-1 made this check unreachable: the field is decoded
# with '<I', so a decoded value could never exceed it, and E-AUTH-06 could not
# fire on any input. (The printed limitation in Table 8 reads "01/19/1987",
# which is before the epoch it is measured from; 01/19/2087 is the date the
# arithmetic gives and the date Table 3 prints for the Location timestamp.)
TS_RANGE = (0, 2 ** 31 - 1)

# ---------------------------------------------------------------------------
#  Trust anchor for the DRIP Link chain of trust (RFC 9575 §6.4.2).
#
#  These are the FALLBACK bench values. The real source of truth is
#  hierarchy.json, loaded at startup if present (or via --anchor FILE), so that
#  swapping in a real DNSSEC-anchored Apex is a DATA change, not a code change.
#
#  Under RFC 9886 §7.1 this anchor is exactly what DNSSEC would establish: the
#  observer would learn the Apex key from a DNSSEC-validated lookup instead of
#  from a constant compiled into it. Until then it is hardcoded, and that is the
#  single most important thing this PoC does NOT yet solve.
#
#  APEX_DET must be the DET that APEX_HI derives under RAA=0/HDA=0/Suite=5. An
#  earlier value of APEX_DET did not, so the anchor failed its own binding, no
#  chain could reach it, and every self-test that built a chain from the bench
#  seeds reported E-LINK-03 on a chain that was in fact correct. The pair below
#  is re-derived by _selftest_anchor() at import time.
# ---------------------------------------------------------------------------
APEX_HI  = bytes.fromhex("4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4")
APEX_DET = bytes.fromhex("200100300000000570F9E8E9B564F448")
ANCHOR_SOURCE = "built-in bench default"


def load_hierarchy(path="hierarchy.json"):
    """Load the trust anchor from hierarchy.json. Returns True if applied.

    PUBLIC data only. An absent file keeps the built-in default, so nothing
    that worked before this file existed breaks because of it.
    """
    global APEX_HI, APEX_DET, ANCHOR_SOURCE
    import json as _json
    try:
        h = _json.load(open(path, encoding="utf-8"))
        a = h["apex"]
        hi, d = bytes.fromhex(a["public_key"]), bytes.fromhex(a["det"])
    except FileNotFoundError:
        return False
    if len(hi) != 32 or len(d) != 16:
        raise ValueError(f"{path}: apex public_key must be 32 B and det 16 B")
    # Never adopt an anchor that does not hold together. An Apex whose DET does
    # not derive from its own key would silently reject every real drone, and
    # the report would blame the drones.
    if HAVE_DET and not det.verify_det_binding(d, hi):
        raise ValueError(f"{path}: the apex DET does not derive from its public "
                         f"key (RFC 9374 3.5.2). Run check_hierarchy.py.")
    APEX_HI, APEX_DET = hi, d
    ANCHOR_SOURCE = path
    return True

def _selftest_anchor():
    """The built-in anchor must satisfy the check it enforces on everyone else.

    A stale APEX_DET is invisible until a chain is walked, at which point every
    endorsement reports E-LINK-03 and the transmitter is blamed for it. Failing
    here instead costs one line at import and cannot be missed.
    """
    if not HAVE_DET:
        return None
    if det.verify_det_binding(APEX_DET, APEX_HI):
        return None
    return (f"built-in anchor is inconsistent: APEX_HI derives "
            f"{det.compute_det(APEX_HI, 0, 0, 5).hex().upper()}, "
            f"not APEX_DET {APEX_DET.hex().upper()}")


ANCHOR_SELFTEST = _selftest_anchor()

# cSHAKE128 customization string for all DRIP Manifest hashes (RFC 9575 §4.4.3)
MAN_HASH_CS = b"Remote ID Auth Hash"


# ---------------------------------------------------------------------------
#  Validators (each appends Finding objects)
# ---------------------------------------------------------------------------
def validate_message(d, where, findings):
    if d.get("_error") == "bad_length":
        findings.append(Finding("E-FMT-03", where, f"{d['length']} bytes"))
        return
    mtype = d.get("type")
    if mtype not in odid.MSG_TYPES:
        findings.append(Finding("E-FMT-01", where, f"type=0x{mtype:X}"))
    if d.get("version") != odid.PROTO_VERSION:
        findings.append(Finding("E-FMT-02", where, f"version=0x{d.get('version'):X}"))
    if mtype == 0xF:
        findings.append(Finding("E-PACK-04", where, "0xF message nested inside a pack"))

    if mtype == 0x2:                                   # authentication page checks
        at = d.get("auth_type")
        if at is not None and 6 <= at <= 9:
            findings.append(Finding("E-AUTH-01", where, f"AuthType={at}"))
        if d.get("page_num") == 0:
            if d.get("last_page_reserved", 0) != 0:
                findings.append(Finding("E-AUTH-04", where,
                                        f"reserved nibble=0x{d['last_page_reserved']:X}"))
            ts = d.get("timestamp_raw")
            if ts is not None and not (TS_RANGE[0] <= ts <= TS_RANGE[1]):
                findings.append(Finding("E-AUTH-06", where, f"ts={ts}"))

    if mtype == 0x0 and d.get("det") is not None:      # DRIP DET prefix check
        prefix28 = int.from_bytes(d["det"], "big") >> 100
        if prefix28 != (int(odid.DET_PREFIX.network_address) >> 100):
            findings.append(Finding("E-DET-01", where, d.get("det_ipv6", "")))


def validate_pack(pack_info, where, findings):
    if pack_info.get("_error"):
        findings.append(Finding("E-PACK-03", where, pack_info["_error"]))
        return
    if pack_info.get("msg_size") != 0x19:
        findings.append(Finding("E-PACK-01", where, f"size=0x{pack_info['msg_size']:X}"))
    n = pack_info.get("count", 0)
    if n < 1 or n > 9:
        findings.append(Finding("E-PACK-02", where, f"N={n}"))
    need = n * odid.MSG_LEN
    have = pack_info.get("bytes_available", 0)
    if need > have:
        findings.append(Finding("E-PACK-03", where, f"need {need}, have {have}"))


def validate_auth(auth, where, findings, now=None, max_age=None):
    expected = list(range(auth["last_page_index"] + 1))
    if auth["pages_present"] != expected:
        findings.append(Finding("E-AUTH-03", where,
                                f"pages={auth['pages_present']} expected={expected}"))
    if not auth["complete"]:
        findings.append(Finding("E-AUTH-05", where, f"declared length={auth['length']}"))
    if auth["auth_type"] == 5:                          # SAM type only meaningful here
        st = auth["sam_type"]
        if st not in odid.SAM_TYPES:
            findings.append(Finding("E-SAM-01", where,
                                    f"SAM=0x{st:02X}" if st is not None else "empty payload"))
    if now is not None and max_age is not None and auth.get("timestamp_unix") is not None:
        age = now - auth["timestamp_unix"]
        if age > max_age or age < -max_age:
            findings.append(Finding("E-FRESH-01", where, f"age={age}s window=+/-{max_age}s"))


# ---------------------------------------------------------------------------
#  Keyring — DET -> Ed25519 public key
#
#  The observer used to hold ONE key (--pubkey) and apply it to every DET it
#  met. That was correct while the transmitter was a single UA. It is not any
#  more: the bench emulator flies up to 3 virtual UAs, each with its OWN key and
#  DET (RFC 9374 3.5.2 binds a DET to the key it was derived from). With one
#  key, two of three drones would fail E-DET-02/E-SIG-01/E-MAN-01 against a key
#  that was never theirs -- a false accusation, not a finding.
# ---------------------------------------------------------------------------

# The three bench identities, as PUBLIC data (det_generator.cpp IDENTITY_TABLE).
# Regenerate with det.py + ed25519.py:
#     seed0 = bytes.fromhex("568BF5E8...C703CCD6")          # slot 0 (legacy)
#     slot_seed = lambda i: det.shake128(b"DRIP PoC UA slot %d" % i, 32)
#     pub = ed25519.derive_pubkey(seed); d = det.compute_det(pub, 1000, 2000)
# NOTE: the observer no longer hard-codes any identities. Every DET->public_key
# comes from the trusted-identities file (hierarchy.json) via
# identity_resolve.iter_known_keys(). This is the SINGLE SOURCE OF TRUTH - there
# is no BUILTIN_KEYS table to drift out of sync with the JSON.


class DnsFallback:
    """Once-per-DET DNS fallback for untrusted DETs seen while reading a file.

    Behaviour (per the agreed spec):
      * The FIRST time an untrusted DET is seen, do ONE DNS lookup (PTR->TXT).
      * Show the user what DNS returned and whether the DET<->key binding holds.
      * If the binding verified, ASK whether to add it to the trust file:
          - yes -> write it into hierarchy.json's ua[] AND add the key to the
                   live keyring, so it is trusted for the rest of THIS run.
          - no  -> record it as "declined"; never look it up again this run.
      * If the binding FAILED, say so plainly and do NOT offer to add it (a key
        that doesn't derive the DET must never enter a trust file). Recorded as
        "seen" so it is not looked up again.
      * If DNS could not answer, say so; recorded as "seen"; not retried.
    Every DET is consulted AT MOST ONCE per run, regardless of outcome.
    """

    def __init__(self, keyring, anchor, dns_server, interactive=True):
        self.keyring = keyring
        self.anchor = anchor
        self.dns_server = dns_server
        self.interactive = interactive
        self._resolver = None
        self.processed = {}   # det_bytes -> outcome string (the once-per-DET gate)

    def _get_resolver(self):
        if self._resolver is None:
            import identity_lookup
            self._resolver = identity_lookup.DnsPythonResolver(server=self.dns_server)
        return self._resolver

    def consider(self, det_bytes):
        """Called by the keyring on a miss. Returns the public key if the DET
        ended up trusted (added), else None. Does the lookup at most once."""
        det_bytes = bytes(det_bytes)
        if det_bytes in self.processed:
            return self.keyring._by_det.get(det_bytes)   # added earlier, or None

        import identity_lookup
        shown = _det_str(det_bytes)
        print(f"\n[DNS] DET {shown} is NOT in the trusted-identities file.")
        try:
            r = identity_lookup.lookup_det(det_bytes, self._get_resolver())
        except Exception as e:
            print(f"[DNS] lookup could not run: {e}")
            self.processed[det_bytes] = "dns-error"
            return None

        if r.error:
            print(f"[DNS] no identity found in DNS: {r.error}")
            self.processed[det_bytes] = "not-in-dns"
            return None

        print(f"[DNS] found: fqdn={r.fqdn}  mfg={r.mfg}  sn={r.sn}  "
              f"model={r.model}  reg_status={r.reg_status}")
        if r.binding_ok is True:
            print(f"[DNS] DET<->key binding VERIFIED (RFC 9374 3.5.2).")
        elif r.binding_ok is False:
            # Say it plainly; do NOT offer to add.
            print(f"[DNS] DET<->key binding FAILED (E-DET-02): the key published "
                  f"in DNS does not derive this DET. NOT offering to add it to "
                  f"the trust file - it is not trustworthy.")
            self.processed[det_bytes] = "binding-failed"
            return None
        else:
            print(f"[DNS] no usable key in the DNS record "
                  f"({r.pubkey_error or 'no key'}); cannot verify. Not adding.")
            self.processed[det_bytes] = "no-key"
            return None

        # binding verified. The DNS key is already in hand (no further lookup).
        # Offer THREE choices, since verifying and persisting are separate acts:
        #   w = write to the trust file AND use the key this run
        #   t = use the key THIS RUN ONLY (verify these messages) - no file write
        #   n = ignore - do not verify, skip for the rest of the run
        if not self.interactive:
            # Non-interactive: verify this run using the DNS key (safe - it was
            # binding-checked), but never write the file unattended.
            self.keyring.add(det_bytes, r.pubkey, source=SRC_REGISTRY,
                             note=str(r.fqdn))
            print(f"[DNS] (--dns-fallback non-interactive: verifying this run "
                  f"with the DNS key; not writing to {self.anchor})")
            self.processed[det_bytes] = "verified-this-run"
            return r.pubkey
        try:
            ans = input(f"[DNS] DET {shown} verified via DNS. "
                        f"[w]rite to {self.anchor}, [t]rust this run only, "
                        f"or [n]o? [w/t/N] ").strip().lower()
        except EOFError:
            ans = ""

        if ans in ("w", "write", "y", "yes"):
            ok, msg = _dns_write_ua_entry(self.anchor, r.det, r.pubkey,
                                          r.reg_status, r.mfg, r.sn, r.model)
            print(f"[DNS] {msg}")
            if ok:
                self.keyring.add(det_bytes, r.pubkey, source=SRC_REGISTRY,
                                 note=str(r.fqdn))     # trusted for rest of run
                self.processed[det_bytes] = "added"
                return r.pubkey
            self.processed[det_bytes] = "write-failed"
            return None
        elif ans in ("t", "trust", "run"):
            # Verify this run only. Uses the key ALREADY fetched above - no second
            # DNS query. Nothing is written to disk.
            self.keyring.add(det_bytes, r.pubkey, source=SRC_REGISTRY,
                             note=str(r.fqdn))
            print(f"[DNS] trusting for THIS RUN only; {self.anchor} not modified.")
            self.processed[det_bytes] = "trusted-this-run"
            return r.pubkey
        else:
            print(f"[DNS] not trusted; ignoring this DET for the rest of the run.")
            self.processed[det_bytes] = "declined"
            return None

    def resolve_parent(self, det_bytes):
        """Resolve a DIME (Apex, RAA or HDA) DET during the endorsement walk.

        RFC 9886 4 publishes exactly these identities, so a parent the capture
        never carried is still reachable when the Observer has connectivity.
        The answer goes through the same once-per-DET gate, the same binding
        check and the same question to the operator as any other DET, and the
        key it yields is recorded with provenance "registry", never "air",
        because the two are not equivalent evidence (RFC 9886 7.1).
        """
        return self.consider(det_bytes)

    def report(self):
        """End-of-run summary of every untrusted DET that was consulted."""
        if not self.processed:
            return
        print("\nDNS fallback summary (untrusted DETs this run):")
        for d, outcome in self.processed.items():
            print(f"  {_det_str(d):40s}  {outcome}")


# ---------------------------------------------------------------------------
#  Key provenance (RFC 9886 §7.1).
#
#  Allowing DNS to supply an anchor for an Apex, RAA or HDA changes the trust
#  model: without DNSSEC the resolver becomes an origin of trust, and an
#  identity anchored that way is not equivalent to one the operator loaded
#  beforehand. The report must therefore say where every key came from, because
#  the claim "this validation was performed with no network" is only checkable
#  if the provenance of each key is on the record.
# ---------------------------------------------------------------------------
SRC_TRUST_FILE = "trust-file"    # loaded from hierarchy.json before the run
SRC_CLI        = "cli"           # --keyring / --pubkey
SRC_AIR        = "air"           # learned from a DRIP Link that reached an anchor
SRC_REGISTRY   = "registry"      # DNS PTR->TXT lookup

SRC_LABEL = {
    SRC_TRUST_FILE: "trust file",
    SRC_CLI:        "command line",
    SRC_AIR:        "air",
    SRC_REGISTRY:   "registry",
}

# Provenances that may act as a starting point for the endorsement traversal.
# A key learned from the air is NOT among them: admitting one would let a
# capture bootstrap its own trust, which is what RFC 9575 §6.4.2 forbids.
ANCHOR_SOURCES = (SRC_TRUST_FILE, SRC_CLI, SRC_REGISTRY)


class KeyOrigin:
    """Where one DET's public key came from, and under whose endorsement."""
    __slots__ = ("source", "parent_det", "note")

    def __init__(self, source, parent_det=None, note=""):
        self.source = source
        self.parent_det = bytes(parent_det) if parent_det else None
        self.note = note

    def label(self):
        base = SRC_LABEL.get(self.source, self.source)
        if self.source == SRC_AIR and self.parent_det:
            return f"{base} (endorsed by {_det_str(self.parent_det)})"
        if self.note:
            return f"{base} ({self.note})"
        return base

    def short(self):
        return SRC_LABEL.get(self.source, self.source)


class BindingRefused(Exception):
    """A key was offered for a DET it does not derive. It never enters the ring."""


class Keyring:
    """Maps a DET to the public key that must have signed for it.

    A --pubkey supplied on the command line is kept as a WILDCARD: it applies to
    any DET with no explicit entry. That preserves the historical behaviour for
    a single unknown drone, while named DET->key entries always win.

    INSERTION IS THE CHOKE POINT. add() re-derives the DET from the key offered
    (RFC 9374 §3.5.2) and refuses the pair when it does not hold, whatever the
    origin: trust file, endorsement received on the air, or DNS answer. The
    check existed before this revision, but it was applied wherever a caller
    remembered to call it, so a new caller could bypass it by omission. A key
    that does not derive its DET is self-assertion, and the keyring is the one
    place that can make that unrepresentable.
    """

    def __init__(self):
        self._by_det = {}
        self._origin = {}       # DET bytes -> KeyOrigin
        self._wildcard = None
        self.fallback = None    # optional DnsFallback, consulted on a miss
        self.refused = []       # (det_bytes, source) pairs rejected at insertion

    def add(self, det_bytes, pub, source=SRC_TRUST_FILE, parent_det=None, note=""):
        """Insert a DET->key pair. Returns True when accepted.

        Raises BindingRefused when det.py is available and the binding fails.
        """
        d, p = bytes(det_bytes), bytes(pub)
        if len(p) != 32:
            raise BindingRefused(f"public key for {_det_str(d)} is {len(p)} bytes, expected 32")
        if HAVE_DET and not det.verify_det_binding(d, p):
            self.refused.append((d, source))
            raise BindingRefused(
                f"{_det_str(d)} does not derive from the key offered by "
                f"{SRC_LABEL.get(source, source)} (RFC 9374 §3.5.2)")
        self._by_det[d] = p
        self._origin[d] = KeyOrigin(source, parent_det, note)
        return True

    def origin(self, det_bytes):
        if det_bytes is None:
            return None
        return self._origin.get(bytes(det_bytes))

    def origins(self):
        return dict(self._origin)

    def anchored_dets(self):
        """DETs whose key predates the capture: the starting points of the walk."""
        return {d for d, o in self._origin.items() if o.source in ANCHOR_SOURCES}

    def set_wildcard(self, pub):
        self._wildcard = bytes(pub)

    def for_det(self, det_bytes):
        if det_bytes is None:
            return self._wildcard
        hit = self._by_det.get(bytes(det_bytes))
        if hit is not None:
            return hit
        # Miss: if a DNS fallback is armed, consult it (once per DET). It may add
        # the key to this keyring, in which case we return it now.
        if self.fallback is not None:
            added = self.fallback.consider(det_bytes)
            if added is not None:
                return added
        return self._wildcard

    def __len__(self):
        return len(self._by_det)

    def __bool__(self):
        return bool(self._by_det) or self._wildcard is not None


def default_keyring(anchor="hierarchy.json"):
    """Build the keyring from the trusted-identities file (single source of
    truth). Returns an empty keyring if the file is missing or unreadable, so
    the observer still runs (it just has no keys to verify against).

    An entry whose key does not derive its DET is skipped and announced. The
    trust file is hand-edited and machine-appended, so a bad entry there is the
    most likely way a broken binding would ever reach the keyring."""
    kr = Keyring()
    try:
        import identity_resolve
        trust = identity_resolve.load_trust(anchor)
        for d_hex, p_hex, label in identity_resolve.iter_known_keys(trust):
            try:
                kr.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex),
                       source=SRC_TRUST_FILE, note=label.split("(")[0].strip())
            except BindingRefused as e:
                print(f"WARNING: {anchor}: entry REFUSED, {e}")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"WARNING: could not load keys from {anchor}: {e}")
    return kr


def trusted_registrar_dets(anchor="hierarchy.json"):
    """DETs of the DIMEs the Observer's owner treats as trusted registrars,
    for RFC 9575 Appendix A.6 (Trusted, blue). Author decision 2026-09-30,
    option A: EVERY RAA and HDA listed in the trust file counts. The Apex is the
    root anchor and is not in the set; it is trusted by being the anchor.
    Returns an empty set if the file is missing or unreadable, so nothing is
    ever Trusted by accident."""
    out = set()
    try:
        import identity_resolve
        trust = identity_resolve.load_trust(anchor)
        for e in list(trust.raas) + list(trust.hdas):
            d = e.get("_det_bytes")
            if d is not None:
                out.add(bytes(d))
    except Exception:
        pass
    return out


def _det_str(det_bytes):
    try:
        return str(ipaddress.IPv6Address(bytes(det_bytes)))
    except Exception:
        return bytes(det_bytes).hex()


# ---------------------------------------------------------------------------
#  Deferred evidence verification (RFC 9575 §6.4.2).
#
#  The Wrapper signature check used to run inline, frame by frame, while the
#  chain walk ran after the whole file had been read. A key learned from a DRIP
#  Link therefore never reached a Wrapper already processed, and E-KEY-01 was
#  decided by arrival order. RFC 9575 §6.4.2 describes an Observer that
#  accumulates evidence and reaches a verdict once enough of it is present, so
#  arrival order must not decide the outcome.
#
#  Every check that needs a key it does not yet have is queued here with
#  everything it needs to run later, and the queue is drained after the chain
#  walk. A DET still without a key at that point produces ONE E-KEY-01 stating
#  how many frames it covers, in place of one finding per frame.
# ---------------------------------------------------------------------------
class DeferredChecks:
    """Checks postponed until the endorsement traversal has learned its keys."""

    def __init__(self):
        self.items = []     # (kind, det_bytes, where, payload)

    def defer(self, kind, det_bytes, where, payload=None):
        self.items.append((kind, bytes(det_bytes), where, payload))

    def drain(self, keys, findings, sink=None, keep_keyless=False):
        """Re-run every queued check, then aggregate the ones still keyless.

        `sink(det_bytes, finding)` receives each finding as well, so a caller
        that attributes findings to an identity does not have to recover the DET
        from the text of the message.

        `keep_keyless` leaves the still-keyless entries on the queue. The live
        observer sets it, because an endorsement that has not arrived yet may
        arrive a second later, and a verdict of "no key" is only final when the
        capture ends.
        """
        keyless = defaultdict(list)          # DET -> [where, ...]
        pending = []
        for kind, det_bytes, where, payload in self.items:
            pub = keys.for_det(det_bytes) if keys is not None else None
            if pub is None:
                keyless[det_bytes].append(where)
                pending.append((kind, det_bytes, where, payload))
                continue
            before = len(findings)
            if kind == "binding":
                _run_det_binding(det_bytes, pub, where, findings)
            elif kind == "wrapper":
                _run_wrapper_signature(pub, payload, where, findings)
            elif kind == "manifest":
                _run_manifest_signature(pub, payload, where, findings)
            if sink is not None:
                for f in findings[before:]:
                    sink(det_bytes, f)
        if not keep_keyless:
            for det_bytes, wheres in keyless.items():
                f = Finding(
                    "E-KEY-01", wheres[0],
                    f"{_det_str(det_bytes)} - no key after the endorsement walk; "
                    f"covers {len(wheres)} deferred check(s)")
                findings.append(f)
                if sink is not None:
                    sink(det_bytes, f)
        self.items = pending if keep_keyless else []
        return keyless


def _run_det_binding(det_bytes, pub, where, findings):
    try:
        if not det.verify_det_binding(det_bytes, pub):
            findings.append(Finding("E-DET-02", where, _det_str(det_bytes)))
    except Exception as e:
        findings.append(Finding("E-DET-02", where, f"check error: {e}"))


def _run_wrapper_signature(pub, payload, where, findings):
    signed, sig, n_msgs = payload
    try:
        if not ed25519_backend.verify(pub, signed, sig):
            findings.append(Finding("E-SIG-01", where, f"{n_msgs} msg(s) in evidence"))
    except Exception as e:
        findings.append(Finding("E-SIG-01", where, f"verify error: {e}"))


def _run_manifest_signature(pub, payload, where, findings):
    signed, sig = payload
    try:
        if not ed25519_backend.verify(pub, signed, sig):
            findings.append(Finding("E-MAN-01", where))
    except Exception as e:
        findings.append(Finding("E-MAN-01", where, f"verify error: {e}"))


def check_det_binding(det_bytes, keys, where, findings, deferred=None):
    """E-DET-02: re-derive the DET from the public key and compare (RFC 9374)."""
    if not HAVE_DET:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01, raised once per DET
    # after the walk rather than once per frame during it.
    if keys is None:
        return
    pub = keys.for_det(det_bytes)
    if pub is None:
        if deferred is not None:
            deferred.defer("binding", det_bytes, where)
        else:
            findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    _run_det_binding(det_bytes, pub, where, findings)


def check_wrapper_signature(auth, decoded_msgs, keys, where, findings, deferred=None):
    """E-SIG-01: verify a DRIP Wrapper (Extended Transport) Ed25519 signature.

    RFC 9575 §4.3.2 + §4.1 Fig 4. The signed bytes are rebuilt as:
        VNB(4) || VNA(4) || Evidence || UA_DET(16)
    where VNB/VNA are the RAW wire bytes (little-endian, not re-encoded, to
    avoid any endianness ambiguity) and Evidence is reconstructed from the
    pack's non-Auth messages (see odid.reconstruct_wrapper_evidence).

    On-wire SAM data (Evidence cleared) = VNB(4)|VNA(4)|DET(16)|Sig(64) = 88 B.
    """
    if not HAVE_ED:
        return
    # A caller that passes NO keyring is not asking for key-based checks, and
    # must stay silent exactly as before. A keyring that simply lacks THIS DET
    # is a different thing entirely - that is E-KEY-01.
    if keys is None:
        return
    if auth.get("auth_type") != 5 or auth.get("sam_type") != 0x02:
        return  # only DRIP Wrapper
    sam = auth.get("sam_data", b"")
    if len(sam) < 88:
        findings.append(Finding("E-SIG-01", where, f"wrapper payload too short ({len(sam)} B)"))
        return
    vnb_bytes = sam[0:4]
    vna_bytes = sam[4:8]
    det_bytes = sam[8:24]
    sig       = sam[24:88]
    # The signed bytes are rebuilt here, while the pack is still in hand, so a
    # deferred check carries everything it needs and never has to re-read the
    # capture.
    evidence  = odid.reconstruct_wrapper_evidence(decoded_msgs)
    signed    = vnb_bytes + vna_bytes + evidence + det_bytes
    payload   = (signed, sig, len(evidence) // 25)
    # Key selection is driven by the DET carried INSIDE the Wrapper, so each UA
    # in a fleet is checked against its own key.
    pub = keys.for_det(det_bytes)
    if pub is None:
        if deferred is not None:
            deferred.defer("wrapper", det_bytes, where, payload)
        else:
            findings.append(Finding("E-KEY-01", where, _det_str(det_bytes)))
        return
    _run_wrapper_signature(pub, payload, where, findings)


# ---------------------------------------------------------------------------
#  Processing
# ---------------------------------------------------------------------------
def process_pack(pack_bytes, where, keys, findings, report, now=None, max_age=None,
                 mac=None, deferred=None):
    pack = odid.split_pack(pack_bytes)
    report.append((where, {"_pack_raw": bytes(pack_bytes)}))   # for Manifest pack-hash cross-check
    validate_pack(pack, where, findings)
    decoded = [odid.decode_message(m) for m in pack.get("messages_raw", [])]
    for idx, d in enumerate(decoded):
        w = f"{where} msg[{idx}]"
        # Synthetic field, same convention as _pack_raw / _auth. Only Format A
        # (air capture) has a MAC at all; the serial/hex formats do not.
        if mac is not None:
            d["_mac"] = mac
        validate_message(d, w, findings)
        report.append((w, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, w, findings, deferred=deferred)

    auths = odid.reassemble_auth(decoded)
    # E-AUTH-02: an Authentication message that no reassembly consumed is a
    # continuation page with no page 0 in front of it. ASTM F3411-22a Table 8
    # states that the page number of a page-0 message must be 0, and
    # reassemble_auth starts only at a page 0, so an unconsumed page is exactly
    # the case Table 8 excludes. Without this the orphan was dropped in silence.
    consumed = set()
    for auth in auths:
        consumed.update(range(auth["start_index"],
                              auth["start_index"] + len(auth["pages_present"])))
    for idx, d in enumerate(decoded):
        if d.get("type") == 0x2 and idx not in consumed:
            findings.append(Finding("E-AUTH-02", f"{where} msg[{idx}]",
                                    f"page={d.get('page_num')} with no page 0 before it"))
    for auth in auths:
        w = f"{where} auth@msg[{auth['start_index']}]"
        validate_auth(auth, w, findings, now=now, max_age=max_age)
        check_wrapper_signature(auth, decoded, keys, w, findings, deferred=deferred)
        report.append((w, {"_auth": auth}))
        # E-FEC-04: RFC 9575 §6.2 - FEC MUST NOT be used in a Message Pack.
        # Checked on complete messages only: the page count must match the FEC
        # layout for its Length (odid.fec_check), which a plain message never
        # does.
        if auth["complete"]:
            k0 = auth["start_index"]
            pages = [bytes(decoded[k0 + k]["raw"]) for k in range(len(auth["pages_present"]))]
            if odid.fec_check(pages)["fec"]:
                findings.append(Finding("E-FEC-04", w,
                                        f"LPI={auth['last_page_index']} Length={auth['length']}"))

    # semantic: DRIP auth present but no DRIP Basic ID in the same pack
    has_drip_auth = any(a["auth_type"] == 5 and a["sam_type"] in odid.SAM_TYPES for a in auths)
    has_drip_bid = any(d.get("type") == 0x0 and d.get("det") is not None for d in decoded)
    if has_drip_auth and not has_drip_bid:
        findings.append(Finding("E-SEM-01", where))


def process_payload(payload, where, keys, findings, report, now=None, max_age=None,
                    mac=None, deferred=None):
    """payload = a Message Pack (first nibble 0xF) or a single 25-byte message."""
    if not payload:
        return
    if (payload[0] >> 4) == 0xF:
        process_pack(payload, where, keys, findings, report, now=now, max_age=max_age,
                     mac=mac, deferred=deferred)
    else:
        d = odid.decode_message(payload[:odid.MSG_LEN])
        # Bluetooth Legacy carries single messages and has an address, so the
        # identity table can attribute them (session 3). Unchanged for the
        # formats that pass no mac.
        if mac is not None:
            d["_mac"] = mac
        validate_message(d, where, findings)
        report.append((where, d))
        if d.get("type") == 0x0 and d.get("det") is not None:
            check_det_binding(d["det"], keys, where, findings, deferred=deferred)


# ---------------------------------------------------------------------------
#  Bluetooth Legacy (session 3) - ASTM F3411-22a §5.4.6, RFC 9575 §5 / §6.1
#
#  odid.LegacyAssembler turns advertisements into messages and Authentication
#  messages; this is where they are judged.
#
#  WHAT IS A FINDING AND WHAT IS NOT. On Legacy each page is one
#  advertisement, and advertisements are lost on the air routinely. A missing
#  page therefore says something about the RADIO PATH, not about the drone,
#  exactly like a W-CAP-01 frame says something about the serial link. So:
#    * an Authentication message with pages missing (beyond what FEC
#      recovers) is COUNTED in capture health and never judged - no E-AUTH-03,
#      no E-AUTH-05, no signature check on half a message;
#    * a Manifest hash with no matching received message is COUNTED, not
#      E-MAN-02: RFC 9575 §4.4 lets an Observer verify the messages it has
#      "without having received them all";
#    * E-FEC-01..03 are raised only on messages that arrived COMPLETE (or were
#      rebuilt), where the bytes themselves contradict RFC 9575 §5 / §6.1.
# ---------------------------------------------------------------------------
def new_legacy_context():
    """Per-run state of the Legacy judge."""
    return {"asm": odid.LegacyAssembler(), "n_msg": 0, "n_auth": 0,
            "health": {"records": 0, "damaged": 0, "messages": 0,
                       "auth_complete": 0, "auth_recovered": 0,
                       "auth_lost": 0, "auth_no_page0": 0, "wrapper_unverified": 0},
            "auth_by_addr": set(), "bid_by_addr": set()}


def process_legacy_event(ev, ctx, keys, findings, report, now=None, max_age=None,
                         deferred=None):
    """Judge one event from odid.LegacyAssembler (see the block comment above)."""
    kind, obj = ev
    h = ctx["health"]
    if kind == "msg":
        rec = obj
        ctx["n_msg"] += 1
        h["messages"] += 1
        where = f"bt[{ctx['n_msg']}] {rec['addr']} cnt=0x{rec['counter']:02X}"
        # Kept for RFC 9575 §4.4.3.1: a Legacy Manifest hashes single messages.
        report.append((where, {"_legacy_raw": bytes(rec["msg"])}))
        process_payload(rec["msg"], where, keys, findings, report, now=now,
                        max_age=max_age, mac=rec["addr"], deferred=deferred)
        if (rec["msg"][0] >> 4) == 0x0:
            d = odid.decode_message(rec["msg"])
            if d.get("det") is not None:
                ctx["bid_by_addr"].add(rec["addr"])
        return

    g = obj
    ctx["n_auth"] += 1
    where = f"bt-auth[{ctx['n_auth']}] {g['addr']} cnt=0x{g['counter']:02X}"
    st = g["status"]
    if st in ("lost", "no_page0"):
        h["auth_lost" if st == "lost" else "auth_no_page0"] += 1
        return
    h["auth_complete" if st == "complete" else "auth_recovered"] += 1

    pages = g["pages"]
    fc = odid.fec_check(pages)
    # E-FEC-03: RFC 9575 §6.1 - FEC MUST be used over Legacy Transports.
    if fc["fec"] is False:
        findings.append(Finding("E-FEC-03", where, f"LPI={g['lpi']} Length={g['length']}"))
    elif fc["fec"] is None:
        findings.append(Finding("E-FEC-01", where, fc["detail"]))
    else:
        if fc["adl_ok"] is False:
            findings.append(Finding("E-FEC-01", where, fc["detail"]))
        # A rebuilt page equals the parity by construction, so parity can only
        # be judged when every page, parity included, arrived.
        if st == "complete" and fc["parity_ok"] is False:
            findings.append(Finding("E-FEC-02", where, fc["detail"]))

    decoded = [odid.decode_message(p) for p in pages]
    auths = odid.reassemble_auth(decoded)
    if not auths:
        return
    auth = auths[0]
    auth["legacy"] = True
    auth["t_us"] = g["t_first_us"]
    if g["recovered_page"] is not None:
        auth["fec_recovered_page"] = g["recovered_page"]
    validate_auth(auth, where, findings, now=now, max_age=max_age)
    if auth.get("sam_type") == 0x02:
        # A Legacy Wrapper carries its Evidence inline (RFC 9575 §4.3.1); the
        # verifier here implements the Extended form (§4.3.2) only. The bench
        # transmitter sends no Wrapper on Bluetooth. Counted, never guessed.
        h["wrapper_unverified"] += 1
    report.append((where, {"_auth": auth, "_mac": g["addr"]}))
    if auth.get("auth_type") == 5 and auth.get("sam_type") in odid.SAM_TYPES:
        ctx["auth_by_addr"].add(g["addr"])


def finish_legacy(ctx, keys, findings, report, now=None, max_age=None, deferred=None):
    """Close the open Authentication messages, then the per-address checks."""
    for ev in ctx["asm"].flush():
        process_legacy_event(ev, ctx, keys, findings, report, now=now,
                             max_age=max_age, deferred=deferred)
    # E-SEM-01 on Legacy: there is no pack, so "in the same pack" becomes "from
    # the same sender address anywhere in the capture". Raised once per address.
    for addr in sorted(ctx["auth_by_addr"] - ctx["bid_by_addr"]):
        findings.append(Finding("E-SEM-01", f"bt {addr}",
                                "DRIP authentication from this address, no DRIP Basic ID"))


def verify_link_chain(bes, findings, now=None, keys=None, resolver=None):
    """Verify a set of DRIP Link Broadcast Endorsements (RFC 9575 §4.2 / §6.4.2).

    ANCHORED TRAVERSAL. The walk starts at the identities the Observer already
    trusts and descends. An endorsement is admitted only once its PARENT is
    trusted, and admitting it makes the child trusted in turn, so trust flows
    Apex -> RAA -> HDA -> UA and never in the other direction. Whatever the walk
    does not reach raises E-LINK-03 naming the parent DET it could not resolve.

    The previous traversal resolved a parent key from any endorsement present in
    the capture, without first establishing that the endorsement itself verified
    and reached an anchor. Two entities endorsing each other with no path to the
    Apex satisfied every check, because E-LINK-03 caught only a chain whose
    parent was absent from the map, never a chain closed on itself. RFC 9575
    §6.4.2 requires the chain to end at an identity the Observer already trusts.

    Starting points, in order:
      * the configured Apex (APEX_DET / APEX_HI)
      * every DET in `keys` whose provenance predates this capture, which is how
        trusting an HDA or an RAA outright makes its children verifiable without
        the levels above being on the air at all
      * a parent resolved through `resolver` (DNS), when one is armed

    Per endorsement:
      E-LINK-01  child DET must bind to child HI (cSHAKE128, via det.py)
      E-LINK-04  BE must be within its VNB..VNA window (only if `now` given)
      E-LINK-02  parent signature over the 72-byte signed region must verify
      E-LINK-03  the walk never reached this endorsement

    Returns the list of (child DET, parent DET, child HI) admitted, so the
    caller can record provenance for each key learned.
    """
    if not (HAVE_DET and HAVE_ED) or not bes:
        return []

    # ---- per-endorsement checks that need no parent ------------------------
    # These are properties of the endorsement alone, so they are reported for
    # every endorsement, reachable or not. An endorsement failing either of them
    # can never teach a key: a child DET that does not derive from the child HI
    # is self-assertion, and an endorsement outside its window has expired.
    usable = {}
    for i, be in enumerate(bes):
        w = f"Link BE child={ipaddress.IPv6Address(be['det_child'])}"
        ok = True

        try:
            if not det.verify_det_binding(be["det_child"], be["hi_child"]):
                findings.append(Finding("E-LINK-01", w))
                ok = False
        except Exception as e:
            findings.append(Finding("E-LINK-01", w, f"binding error: {e}"))
            ok = False

        # UNITS. decode_link_sam() returns vnb/vna as RAW DRIP-epoch seconds
        # (seconds since 2019-01-01); it does NOT add EPOCH_2019, while `now` is
        # a Unix timestamp, which is what --now is documented as and what
        # validate_auth() compares against auth["timestamp_unix"]. Comparing the
        # two directly placed `now` in the year 2075, so E-LINK-04 fired on
        # every endorsement whenever a reference time was supplied. The default
        # of None skips the check, which is why it stayed hidden until the
        # real-time observer began passing an actual clock.
        if now is not None:
            now_drip = now - odid.EPOCH_2019
            if not (be["vnb"] <= now_drip <= be["vna"]):
                findings.append(Finding("E-LINK-04", w,
                                        f"vnb={be['vnb']} vna={be['vna']} "
                                        f"now={now_drip:.0f} (DRIP epoch)"))
                ok = False
        usable[i] = ok

    # ---- the anchored walk --------------------------------------------------
    trusted = {bytes(APEX_DET): bytes(APEX_HI)}
    if keys is not None:
        for d in keys.anchored_dets():
            pub = keys.for_det(d)
            if pub is not None:
                trusted[bytes(d)] = bytes(pub)

    admitted = []
    pending = list(range(len(bes)))

    def _try_round():
        """One pass over the pending endorsements. Returns True if any admitted."""
        progress = False
        for i in list(pending):
            be = bes[i]
            parent = bytes(be["det_parent"])
            parent_hi = trusted.get(parent)
            if parent_hi is None:
                continue
            pending.remove(i)
            w = f"Link BE child={ipaddress.IPv6Address(be['det_child'])}"
            if not ed25519_backend.verify(parent_hi, be["signed_region"], be["sig"]):
                findings.append(Finding("E-LINK-02", w))
                continue
            # The parent vouched for this child, so the child may now vouch for
            # its own children. A failed E-LINK-01 or E-LINK-04 above stops the
            # key entering the trusted set while leaving the signature verdict
            # on the record.
            if usable[i]:
                child = bytes(be["det_child"])
                trusted[child] = bytes(be["hi_child"])
                admitted.append((child, parent, bytes(be["hi_child"])))
                progress = True
        return progress

    while _try_round():
        pass

    # ---- a registry lookup may supply a parent the capture never carried ----
    # RFC 9886 §4 publishes the DIME identities the air interface assumes the
    # Observer already holds. Consulting it here is the only point at which an
    # unresolvable parent can still be anchored, and any key it supplies is
    # recorded with provenance "registry" rather than "air".
    if resolver is not None and pending:
        for i in list(pending):
            parent = bytes(bes[i]["det_parent"])
            if parent in trusted:
                continue
            pub = resolver(parent)
            if pub is not None:
                trusted[parent] = bytes(pub)
        while _try_round():
            pass

    for i in pending:
        be = bes[i]
        w = f"Link BE child={ipaddress.IPv6Address(be['det_child'])}"
        findings.append(Finding("E-LINK-03", w,
            f"the walk never reached this endorsement: parent "
            f"{ipaddress.IPv6Address(be['det_parent'])} is not trusted and was "
            f"not endorsed by anything that is"))

    # Record every key the walk learned, with the parent that endorsed it. A key
    # learned here is valid for THIS RUN ONLY; nothing writes it to the trust
    # file (see _offer_trust()).
    if keys is not None:
        for child, parent, hi in admitted:
            if keys.origin(child) is not None:
                continue
            try:
                keys.add(child, hi, source=SRC_AIR, parent_det=parent)
            except BindingRefused:
                pass
    return admitted


def _collect_link_bes(report):
    """Extract unique DRIP Link BEs (SAM type 0x01) from the decoded report."""
    seen = set()
    bes = []
    for _w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x01:
            continue
        be = odid.decode_link_sam(a.get("sam_data", b""))
        if be is None:
            continue
        key = be["det_child"] + be["det_parent"] + be["sig"]
        if key in seen:
            continue
        seen.add(key)
        bes.append(be)
    return bes


def _man_hash8(data):
    """cSHAKE128(data, 64 bits, N='', S='Remote ID Auth Hash') -> 8 bytes (RFC 9575 §4.4.3)."""
    return det.cshake128(bytes(data), 8, N=b'', S=MAN_HASH_CS)


def _collect_manifests(report):
    """Unique DRIP Manifests (SAM 0x03) in report order."""
    seen, out = set(), []
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("sam_type") != 0x03:
            continue
        m = odid.decode_manifest_sam(a.get("sam_data", b""))
        if m is None:
            continue
        key = bytes(a["sam_data"])
        if key in seen:
            continue
        seen.add(key)
        # Carried for the Legacy rules of verify_manifests (session 3).
        m["_legacy"] = bool(a.get("legacy"))
        m["_t_us"] = a.get("t_us")
        out.append((w, m))
    return out


def _collect_legacy_msg_hashes(report):
    """Hash every single ASTM message received over Legacy Transport
       (RFC 9575 §4.4.3.1: the full 25-octet message, Message Counter excluded -
       the counter sits outside those 25 octets in the advertisement)."""
    return {_man_hash8(d["_legacy_raw"]) for _w, d in report if "_legacy_raw" in d}


def _collect_pack_hashes(report):
    """Hash every observed Message Pack (RFC 9575 §4.4.3.2: full pack, no counter)."""
    return {_man_hash8(d["_pack_raw"]) for _w, d in report if "_pack_raw" in d}


def _collect_link_hashes(report):
    """Hash every observed DRIP Link full SAM (0x01 || sam_data), as the firmware does."""
    hs = set()
    for _w, d in report:
        a = d.get("_auth")
        if a and a.get("sam_type") == 0x01:
            hs.add(_man_hash8(bytes([0x01]) + bytes(a.get("sam_data", b""))))
    return hs


def collect_identities(report, keys=None):
    """Group everything observed by DRIP identity.

    Keyed on the DET, not the MAC: the DET *is* the identity (RFC 9374 §3.5.2
    binds it to a key). The MAC is only the radio that carried it, and ASTM
    F3411-22a §5.4.5.6 NOTE 2 explicitly permits a UA using Specific Session ID
    Type (which DRIP is, ID Type 4) to rotate MACs for privacy. So "how many
    drones are in the air" = how many distinct DETs.
    """
    ids = {}

    def slot(det_b):
        return ids.setdefault(bytes(det_b), {
            "macs": set(), "packs": 0, "wrap": set(), "man": set(), "key": None})

    # Basic ID messages -> DET, MAC, pack count
    for w, d in report:
        if d.get("type") == 0x0 and d.get("det"):
            e = slot(d["det"])
            e["packs"] += 1
            if d.get("_mac"):
                e["macs"].add(d["_mac"])

    # Wrapper signatures (unique), keyed by the DET inside the SAM
    for w, d in report:
        a = d.get("_auth")
        if not a or a.get("auth_type") != 5 or a.get("sam_type") != 0x02:
            continue
        sam = a.get("sam_data", b"")
        if len(sam) < 88:
            continue
        slot(sam[8:24])["wrap"].add(bytes(sam[24:88]))

    # Manifest signatures (unique)
    for w, m in _collect_manifests(report):
        if m.get("det"):
            slot(m["det"])["man"].add(bytes(m["sig"]))

    if keys is not None:
        for det_b, e in ids.items():
            e["key"] = keys.for_det(det_b)
    return ids


def report_identities(ids, findings, keys=None):
    """Print the identity table and raise W-MAC-02 where warranted.

    The 'key from' column is the provenance of the key each verdict rests on.
    Without it the report cannot distinguish a verdict reached with no network
    from one that depended on a registry answer, and that distinction is the
    whole point of the offline case (RFC 9434 §1.2.1).
    """
    print(f"\nIdentities observed: {len(ids)} drone(s)")
    if not ids:
        return
    print(f"\n  {'#':<3}{'DET':<40} {'MAC(s)':<20} {'packs':>6}  "
          f"{'key from':<38} auth")
    for i, (det_b, e) in enumerate(sorted(ids.items(), key=lambda kv: -kv[1]["packs"]), 1):
        macs = sorted(e["macs"]) or ["(n/a)"]
        origin = keys.origin(det_b) if keys is not None else None
        if e["key"] is None:
            keylab, auth = "-", "NO KEY - not verified"
        else:
            keylab = origin.label() if origin else "wildcard (--pubkey)"
            auth = f"OK  ({len(e['wrap'])} wrap, {len(e['man'])} man)"
        print(f"  {i:<3}{_det_str(det_b):<40} {macs[0]:<20} {e['packs']:>6}  "
              f"{keylab:<38} {auth}")
        for extra in macs[1:]:
            print(f"  {'':<3}{'':<40} {extra:<20}")
        # W-MAC-02: NOT an ASTM violation (see errors.py) — a bench expectation.
        if len(e["macs"]) > 1:
            findings.append(Finding("W-MAC-02", _det_str(det_b),
                                    f"{len(e['macs'])} MACs: {', '.join(macs)}"))
    # One MAC carrying several DETs shows above as rows sharing a MAC. ASTM
    # F3411-22a 5.4.5.6 NOTE 2 permits the opposite case (one DET, many MACs)
    # and says nothing about this one. No validator raises a code for it.


# Two Legacy Manifests further apart than this are not chain-compared (one or
# more lost in between). The RFC 9575 §6.4 schedule sends one per second.
LEGACY_MAN_GAP_US = 1_600_000

# Wi-Fi counterpart of LEGACY_MAN_GAP_US (session 3, 2026-10-04, author
# decision): a beacon lost on the air takes its Manifest with it, and the next
# Manifest's Prev then points at one the Observer never saw. The bench sends
# one Manifest per drone every 3 s (Cycle C of A/B/C, one pack per second), so
# two Wi-Fi Manifests more than 1.5 x that apart have at least one lost between
# them and are NOT chain-compared; the gap is counted. Captures without receive
# times (Formats W, B, L) keep the strict comparison.
WIFI_MAN_GAP_US = 4_500_000


def _tag_receive_time(report, start, t_us):
    """Give every Authentication message appended to `report` since index
    `start` the sniffer receive time of its frame (Format A meta t_us), so
    verify_manifests can tell consecutive Wi-Fi Manifests from ones with a lost
    Manifest between them (session 3)."""
    if t_us is None:
        return
    for _w, d in report[start:]:
        a = d.get("_auth")
        if a is not None and a.get("t_us") is None:
            a["t_us"] = t_us


def manifest_pair_comparable(kind, t_us, prev_kind, prev_t_us):
    """May two consecutive Manifests of one UA be chain-compared (E-MAN-04)?

    kind / prev_kind: "bt" (Legacy, sniffer clock), "wifi" (receive time
    known), or None (no receive time: Formats W/B/L). Used by verify_manifests
    and by live_state.py, so batch and live apply one rule.
      * both None            -> True (strict, as before session 3)
      * same timed transport -> True only if they arrived closer than that
                                transport's gap (no Manifest lost between)
      * anything else        -> False (a radio switch or mixed timing: the two
                                clocks are unrelated)"""
    if kind is None and prev_kind is None:
        return True
    if kind != prev_kind or t_us is None or prev_t_us is None:
        return False
    gap = LEGACY_MAN_GAP_US if kind == "bt" else WIFI_MAN_GAP_US
    return 0 <= t_us - prev_t_us < gap


# How long a Bluetooth Legacy Manifest may wait for the BE:HDA,UA Link its
# hash references, before E-MAN-03 (session 3, 2026-10-04). On Legacy a Link
# arrives one page per second (RFC 9575 §6.4), 8 pages, and the rotation does
# not start with it, so it can take tens of seconds - and right after an
# identity switch or a reset it has not been sent at all yet. RFC 9575 §6.3
# only requires the HDA,UA Link "at least once per minute", so an Observer
# that waits less than that would report a Link that is merely on its way.
LEGACY_LINK_WAIT_S = 60


def verify_manifests(report, findings, keys=None, now=None, deferred=None):
    """Verify DRIP Manifests (RFC 9575 §4.4). Cross-checks against packs/links
       observed elsewhere in the same capture; chains manifests by Prev/Curr."""
    if not HAVE_DET:
        return
    mans = _collect_manifests(report)
    if not mans:
        return
    pack_hashes = _collect_pack_hashes(report)
    link_hashes = _collect_link_hashes(report)
    msg_hashes = _collect_legacy_msg_hashes(report)
    prev_t_by_det = {}
    # ------------------------------------------------------------------
    # FLEET FIX: the Manifest hash chain is PER UA (RFC 9575 4.4.2) — each
    # aircraft maintains its own Prev/Curr ledger. This used to walk ONE global
    # cursor over every manifest in the capture, which is right for one drone
    # and wrong for several: with 3 UAs interleaved it compares drone 0's Curr
    # against drone 1's Prev and reports E-MAN-04 on essentially every manifest.
    # The chain is now tracked per DET. (decode_manifest_sam already returns the
    # UA DET, so no new decoding is needed.)
    # ------------------------------------------------------------------
    prev_by_det = {}
    for w, m in mans:
        det_b = m.get("det")
        pub = keys.for_det(det_b) if keys is not None else None
        # E-MAN-01: UA signature over VNB|VNA|Evidence|DET — with THIS UA's key
        # keys is None => caller did not ask for signature checks (silent).
        if HAVE_ED and keys is not None and pub is None:
            if deferred is not None:
                deferred.defer("manifest", det_b, w, (m["signed_region"], m["sig"]))
            else:
                findings.append(Finding("E-KEY-01", w, _det_str(det_b)))
        elif HAVE_ED and pub and not ed25519_backend.verify(pub, m["signed_region"], m["sig"]):
            findings.append(Finding("E-MAN-01", w))
        # E-MAN-05: self-hash = cSHAKE128(Prev | null | Link | ASTM hashes)
        calc = _man_hash8(m["prev"] + b"\x00" * 8 + m["link_hash"] + b"".join(m["astm_hashes"]))
        if calc != m["curr"]:
            findings.append(Finding("E-MAN-05", w, f"curr={m['curr'].hex()} calc={calc.hex()}"))
        legacy = m.get("_legacy", False)
        # E-MAN-02: each ASTM hash must match an observed pack (Extended,
        # §4.4.3.2) - or, for a Manifest received over Legacy, an observed
        # single message (§4.4.3.1). On Legacy an unmatched hash is a message
        # that was not RECEIVED, which RFC 9575 §4.4 explicitly allows ("without
        # having received them all"); it is counted, not reported.
        for h in m["astm_hashes"]:
            if h in pack_hashes or h in msg_hashes:
                continue
            if legacy:
                capture_health["man_hash_unreceived"] = capture_health.get("man_hash_unreceived", 0) + 1
            else:
                findings.append(Finding("E-MAN-02", w, f"unmatched pack hash {h.hex()}"))
        # E-MAN-03: link hash must match an observed BE:HDA,UA. On Legacy the
        # Link arrives one page per second; if no Link was received at all the
        # check cannot be made and is counted instead.
        if m["link_hash"] not in link_hashes:
            # Legacy: not checkable when no Link was received at all, or when
            # the capture ends less than LEGACY_LINK_WAIT_S after this Manifest
            # (the RFC 9575 §6.3 once-per-minute Link may still have been due).
            t_end = capture_health.get("bt", {}).get("t_last_us")
            t_man = m.get("_t_us")
            too_short = (legacy and t_end is not None and t_man is not None
                         and t_end - t_man < LEGACY_LINK_WAIT_S * 1_000_000)
            if legacy and (not link_hashes or too_short):
                capture_health["man_link_unchecked"] = capture_health.get("man_link_unchecked", 0) + 1
            else:
                findings.append(Finding("E-MAN-03", w, f"unmatched link hash {m['link_hash'].hex()}"))
        # E-MAN-04: chain, PER UA (skip the first manifest of each UA, whose
        # Prev is that drone's seed nonce).
        # Legacy: Manifests are lost on the air far more often than packs, and
        # a lost one makes the next Prev "wrong" through no fault of the UA. Two
        # Legacy Manifests are compared only when they are consecutive in time
        # (under LEGACY_MAN_GAP_US apart; the schedule sends one per second).
        # A Legacy/Wi-Fi pair across a radio switch is not compared: the two
        # capture clocks are unrelated. Gaps are counted.
        # Wi-Fi (session 3): the same rule when the capture has receive times
        # (Format A), via manifest_pair_comparable().
        prev_curr = prev_by_det.get(det_b)
        kind = "bt" if legacy else ("wifi" if m.get("_t_us") is not None else None)
        prev_kind, prev_t = prev_t_by_det.get(det_b, (None, None))
        comparable = manifest_pair_comparable(kind, m.get("_t_us"), prev_kind, prev_t)
        if prev_curr is not None and m["prev"] != prev_curr:
            if comparable:
                findings.append(Finding("E-MAN-04", w,
                                        f"prev={m['prev'].hex()} expected={prev_curr.hex()}"))
            else:
                capture_health["man_chain_gaps"] = capture_health.get("man_chain_gaps", 0) + 1
        prev_by_det[det_b] = m["curr"]
        prev_t_by_det[det_b] = (kind, m.get("_t_us"))


class UnknownFormatError(Exception):
    """No parser recognised the input. Raised instead of guessing."""


# Populated by run() for Format A; read by print_report(). Kept module-level so
# run() can keep returning exactly 3 values (make_vectors.py unpacks 3).
capture_health = {}


def run(text, keys=None, now=None, max_age=None, pub=None, progress=False,
        resolver=None):
    """Decode + validate `text`. Returns (format_label, report, findings).

    `pub` is a BACK-COMPAT shim for callers that predate the keyring
    (make_vectors.py passes pub=UA_PUB). A bare key means "apply this to any
    DET", which is exactly a wildcard entry -- so it is wrapped into one rather
    than being a second code path that could drift.

    Auto-detects Format BT (DRIP_Sniffer Bluetooth Legacy capture, possibly
    mixed with Format A - session 3), Format L (ESP32 serial log), Format A (DRIP_Sniffer air
    capture), Format W (Wireshark bytes export) or Format B (flat hex).

    Raises UnknownFormatError if none of them match.

    Every branch is now a POSITIVE test. Format B used to be the unconditional
    `else`, so an unrecognised file was DECLARED to be flat hex and decoded
    anyway. Handed an air capture, that turned a flawless 555-frame file into
    10157 findings and read as "your firmware is broken" -- a wrong answer
    delivered confidently, which is worse than no answer.
    """
    if pub is not None and keys is None:
        keys = Keyring()
        keys.set_wildcard(pub)

    findings = []
    report = []
    deferred = DeferredChecks()
    capture_health.clear()
    if odid.looks_like_format_bt(text):
        # Bluetooth Legacy capture (session 3), possibly MIXED with Wi-Fi
        # Format A segments when the sniffer switched radios mid-capture. The
        # segments are processed in file order so a UA's Manifest chain is seen
        # in the order it was sent. Checked BEFORE Format A because the
        # sniffer's boot banner ('DRIP-SNIFFER') would otherwise claim the file.
        segs = odid.split_capture_segments(text)
        ctx = new_legacy_context()
        fi = 0
        for kind, chunk in segs:
            if kind == "BT":
                recs, dmg = odid.parse_format_bt(chunk)
                ctx["health"]["records"] += len(recs) + len(dmg)
                ctx["health"]["damaged"] += len(dmg)
                for meta, got in dmg:
                    findings.append(Finding("W-CAP-01", "capture",
                                            f"BT {meta.get('addr')} declared len="
                                            f"{meta.get('len')}, got {got} B"))
                for rec in recs:
                    ctx["health"]["t_last_us"] = max(ctx["health"].get("t_last_us", 0),
                                                     rec["t_us"])
                    for ev in ctx["asm"].feed(rec):
                        process_legacy_event(ev, ctx, keys, findings, report, now=now,
                                             max_age=max_age, deferred=deferred)
            else:
                a_frames, a_damaged = odid.parse_format_a(chunk)
                for meta, got in a_damaged:
                    findings.append(Finding("W-CAP-01", "capture",
                                            f"declared len={meta.get('len')}, got {got} B"))
                capture_health["frames"] = capture_health.get("frames", 0) + len(a_frames) + len(a_damaged)
                capture_health["damaged"] = capture_health.get("damaged", 0) + len(a_damaged)
                for meta, frame in a_frames:
                    ie = odid.extract_drip_ie(frame)
                    if ie is None:
                        continue
                    hdr = odid.parse_mac_header(frame)
                    tag = odid.mac_str(hdr["addr2"]) if hdr else "??:??:??:??:??:??"
                    where = f"frame[{fi}] {tag} cnt=0x{ie['counter']:02X}"
                    fi += 1
                    n0 = len(report)
                    process_payload(ie["payload"], where, keys, findings, report,
                                    now=now, max_age=max_age, mac=tag, deferred=deferred)
                    _tag_receive_time(report, n0, meta.get("t_us"))
        finish_legacy(ctx, keys, findings, report, now=now, max_age=max_age,
                      deferred=deferred)
        capture_health["bt"] = dict(ctx["health"])
        fmt = ("A+BT (mixed Wi-Fi / Bluetooth air capture - DRIP_Sniffer)"
               if capture_health.get("frames") else
               "BT (Bluetooth Legacy air capture - DRIP_Sniffer)")
    elif odid.looks_like_format_l(text):
        fmt = "L (ESP32 serial log)"
        for entry in odid.parse_format_l(text):
            where = (f"tx[{entry['tx_cnt']:#04x}] "
                     f"cnt=0x{entry['counter']:02X} "
                     f"cycle={entry['cycle']}")
            process_payload(entry["pack_bytes"], where, keys,
                            findings, report, now=now, max_age=max_age,
                            deferred=deferred)
    elif odid.looks_like_format_a(text):
        fmt = "A (air capture - DRIP_Sniffer)"
        a_frames, a_damaged = odid.parse_format_a(text)
        # A frame whose byte count contradicts the sniffer's own '#F len='
        # never arrived intact. It cannot testify about the drone that sent it,
        # so it is reported as capture damage rather than decoded into
        # DRIP "violations" that are really serial byte loss.
        for meta, got in a_damaged:
            findings.append(Finding("W-CAP-01", "capture",
                                    f"declared len={meta.get('len')}, got {got} B"))
        capture_health["frames"] = len(a_frames) + len(a_damaged)
        capture_health["damaged"] = len(a_damaged)
        for fi, (meta, frame) in enumerate(a_frames):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue          # e.g. a frame truncated when capture stopped
            hdr = odid.parse_mac_header(frame)
            # The transmitter MAC goes in the label so every finding is
            # attributable when several drones are on the air. No check
            # binds the MAC to the DET; the DET is the identity.
            tag = odid.mac_str(hdr["addr2"]) if hdr else "??:??:??:??:??:??"
            where = f"frame[{fi}] {tag} cnt=0x{ie['counter']:02X}"
            n0 = len(report)
            process_payload(ie["payload"], where, keys, findings, report,
                            now=now, max_age=max_age, mac=tag, deferred=deferred)
            _tag_receive_time(report, n0, meta.get("t_us"))
            if progress and fi and fi % 2000 == 0:
                print(f"# {fi} frames...", file=sys.stderr, flush=True)
    elif odid.looks_like_format_w(text):
        fmt = "W (Wireshark bytes export)"
        for fi, frame in enumerate(odid.parse_format_w(text)):
            ie = odid.extract_drip_ie(frame)
            if ie is None:
                continue
            where = f"frame[{fi}] cnt=0x{ie['counter']:02X}"
            process_payload(ie["payload"], where, keys, findings, report, now=now,
                            max_age=max_age, deferred=deferred)
    elif odid.looks_like_format_b(text):
        fmt = "B (flat hex)"
        for ri, (rec, _expect) in enumerate(odid.parse_format_b(text)):
            process_payload(rec, f"record[{ri}]", keys, findings, report, now=now,
                            max_age=max_age, deferred=deferred)
    else:
        raise UnknownFormatError(odid.diagnose_format(text))

    # ORDER MATTERS, and it is the order RFC 9575 6.4.2 describes: accumulate
    # the evidence first, then walk the chain of endorsements, and only then
    # judge the evidence, with every key the walk has learned in hand. Running
    # the walk after the decode pass is what makes a Wrapper that arrived before
    # its DRIP Link verifiable at all.
    verify_link_chain(_collect_link_bes(report), findings, now=now, keys=keys,
                      resolver=resolver)
    # DRIP Manifest verification: signature, self-hash, pack/link cross-check, chaining
    verify_manifests(report, findings, keys=keys, now=now, deferred=deferred)
    # Everything postponed for want of a key runs here, and a DET still without
    # one produces a single E-KEY-01 rather than one per frame.
    deferred.drain(keys, findings)
    return fmt, report, findings


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
def _fmt_msg_line(where, d):
    if "_auth" in d:
        a = d["_auth"]
        sam = a.get("sam_name") or (f"0x{a['sam_type']:02X}" if a["sam_type"] is not None else "?")
        return (f"  {where}: Auth reassembled  type={a['auth_type']} "
                f"pages={a['pages_present']} len={a['length']} "
                f"SAM={sam} complete={a['complete']}")
    t = d.get("type_name", "?")
    extra = ""
    if d.get("type") == 0x0 and d.get("det_ipv6"):
        extra = f"  DET={d['det_ipv6']}"
    elif d.get("type") == 0x3:
        extra = f"  desc='{d.get('description','')}'"
    elif d.get("type") == 0x5:
        extra = f"  op='{d.get('operator_id','')}'"
    elif d.get("type") == 0x4:
        extra = f"  lat={d.get('operator_lat'):.5f} lon={d.get('operator_lon'):.5f}"
    return f"  {where}: {t}{extra}"


def report_key_provenance(keys):
    """Summarise where the run's key material came from.

    Stated as a count per origin so a reader can tell at a glance whether the
    run needed the network. A run whose every key is "trust file" or "air" was
    performed offline; one key from the registry means it was not.
    """
    if keys is None or not keys.origins():
        return
    counts = Counter(o.source for o in keys.origins().values())
    parts = [f"{counts[s]} from {SRC_LABEL[s]}" for s in
             (SRC_TRUST_FILE, SRC_CLI, SRC_AIR, SRC_REGISTRY) if counts.get(s)]
    print()
    print("Key provenance: " + ", ".join(parts))
    if counts.get(SRC_AIR):
        print("  Keys learned from the air are valid for THIS RUN ONLY. They "
              "reached a trust anchor (RFC 9575 6.4.2), and nothing writes them "
              "to the trusted-identities file; use --offer-trust to be asked.")
    if counts.get(SRC_REGISTRY):
        print("  Keys obtained from the registry make this run NETWORK-DEPENDENT. "
              "Without DNSSEC the resolver is itself an origin of trust "
              "(RFC 9886 7.1), so such an identity is not equivalent to one the "
              "operator loaded beforehand.")
    if keys.refused:
        print(f"  {len(keys.refused)} key(s) REFUSED at insertion: the DET did "
              f"not derive from the key offered (RFC 9374 3.5.2).")


def print_report(fmt, report, findings, verbose=False, keys=None):
    print(f"Input format: {fmt}")
    msg_items = [(w, d) for w, d in report if "_pack_raw" not in d and "_legacy_raw" not in d]
    print(f"DRIP payloads decoded: {len({w.split(' msg')[0].split(' auth')[0] for w, _ in msg_items})}")
    print(f"Decoded items: {len(msg_items)}")
    if not HAVE_DET:
        print("(note: det.py not importable - DET<->key binding check disabled)")

    # message-type histogram
    hist = Counter()
    for _w, d in msg_items:
        if "_auth" in d:
            hist["Authentication (reassembled)"] += 1
        else:
            hist[d.get("type_name", "?")] += 1
    print("\nMessage-type counts:")
    for name, c in hist.most_common():
        print(f"  {c:6d}  {name}")

    if verbose:
        print("\nDecoded items:")
        for w, d in msg_items:
            print(_fmt_msg_line(w, d))

    # Capture health, printed BEFORE the identity table: if the capture itself
    # is damaged, that context has to arrive before any finding is read.
    if capture_health.get("frames"):
        tot = capture_health["frames"]; dmg = capture_health["damaged"]
        pct = 100.0 * (tot - dmg) / tot
        print(f"\nCapture health: {tot - dmg:,}/{tot:,} frames intact ({pct:.2f}%)")
        if dmg:
            print(f"  {dmg} frame(s) DISCARDED - damaged in the capture pipeline "
                  f"(serial byte loss), not on the air.")
            print(f"  These are W-CAP-01, not DRIP defects. Findings from the "
                  f"surrounding frames may be collateral.")

    if capture_health.get("man_chain_gaps") and not capture_health.get("bt"):
        print(f"  {capture_health['man_chain_gaps']} Manifest chain gap(s): a Manifest "
              f"beacon was lost or the drone restarted, so the next one was not "
              f"chain-compared "
              f"(E-MAN-04 needs consecutive Manifests, < "
              f"{WIFI_MAN_GAP_US / 1e6:.1f} s apart)")
    bt = capture_health.get("bt")
    if bt:
        print(f"\nBluetooth Legacy capture health (session 3):")
        print(f"  adverts {bt['records']:,} (damaged in the capture pipeline: {bt['damaged']}), "
              f"distinct ASTM messages {bt['messages']:,}")
        n_auth = bt["auth_complete"] + bt["auth_recovered"] + bt["auth_lost"] + bt["auth_no_page0"]
        print(f"  Authentication messages {n_auth}: complete {bt['auth_complete']}, "
              f"rebuilt by FEC {bt['auth_recovered']}, lost (2+ pages missing) "
              f"{bt['auth_lost']}, page 0 never received {bt['auth_no_page0']}")
        print("  Lost pages are a RADIO-PATH fact, not a drone defect: those messages "
              "were not judged.")
        extra = []
        if capture_health.get("man_hash_unreceived"):
            extra.append(f"{capture_health['man_hash_unreceived']} Manifest hash(es) of "
                         f"messages not received (RFC 9575 4.4 allows this)")
        if capture_health.get("man_chain_gaps"):
            extra.append(f"{capture_health['man_chain_gaps']} Manifest chain gap(s) "
                         f"after a lost Manifest (not compared)")
        if capture_health.get("man_link_unchecked"):
            extra.append(f"{capture_health['man_link_unchecked']} Manifest(s) whose Link "
                         f"could not be checked (none received, or the capture ended "
                         f"< {LEGACY_LINK_WAIT_S} s after the Manifest; RFC 9575 6.3)")
        if bt.get("wrapper_unverified"):
            extra.append(f"{bt['wrapper_unverified']} Legacy Wrapper(s) not verified "
                         f"(RFC 9575 4.3.1 form not implemented)")
        for e in extra:
            print(f"  {e}")

    # Identity report. Raises W-MAC-02, so it must run before findings are
    # grouped for printing.
    idents = collect_identities(report, keys=keys)
    report_identities(idents, findings, keys=keys)
    report_key_provenance(keys)

    # ---- findings grouped by DET (which drone) ----------------------------
    # Answers "which identity do these findings belong to". A finding is linked
    # to a DET by either (a) its detail string being that DET, or (b) a MAC in
    # its `where` that the identity table maps to that DET. Findings with no DET
    # link (format/pack-level) are bucketed as "unattributed".
    if findings:
        det_strs = {_det_str(db): db for db in idents}          # "2001:.." -> bytes
        mac_to_det = {}                                         # "aa:bb.." -> det str
        for db, e in idents.items():
            for mac in e["macs"]:
                mac_to_det[str(mac).lower()] = _det_str(db)

        def det_of(f):
            # (a) DET appears verbatim in the detail
            if f.detail:
                for ds in det_strs:
                    if ds in f.detail:
                        return ds
            # (b) a known MAC appears in the location string
            w = (f.where or "").lower()
            for mac, ds in mac_to_det.items():
                if mac in w:
                    return ds
            return None

        per_det = defaultdict(lambda: defaultdict(int))         # detstr -> {eid: count}
        unattributed = defaultdict(int)
        for f in findings:
            ds = det_of(f)
            if ds is None:
                unattributed[f.error_id] += 1
            else:
                per_det[ds][f.error_id] += 1

        print("\nFindings by DET:")
        # Show every observed identity, even those with 0 findings (so a trusted
        # drone visibly contributes nothing).
        for db, e in sorted(idents.items(), key=lambda kv: -kv[1]["packs"]):
            ds = _det_str(db)
            counts = per_det.get(ds, {})
            total = sum(counts.values())
            keylab = "trusted" if e["key"] else "NO KEY"
            macs = ",".join(sorted(str(m) for m in e["macs"])) or "(n/a)"
            print(f"  {ds}  [{keylab}]  {total} finding(s)")
            if counts:
                brk = ", ".join(f"{eid} x{n}" for eid, n in sorted(counts.items()))
                print(f"        {brk}")
        if unattributed:
            tot = sum(unattributed.values())
            brk = ", ".join(f"{eid} x{n}" for eid, n in sorted(unattributed.items()))
            print(f"  (unattributed - format/pack level)  {tot} finding(s)")
            print(f"        {brk}")

    # findings grouped by error id
    print("\nFindings:")
    if not findings:
        print("  (none)")
    else:
        by_id = defaultdict(list)
        for f in findings:
            by_id[f.error_id].append(f)
        for eid in sorted(by_id):
            desc, constraint = ERROR_CATALOG.get(eid, ("?", ""))
            items = by_id[eid]
            print(f"  {eid}  x{len(items)}  {desc}")
            print(f"          constraint: {constraint}")
            for f in items[:5 if not verbose else len(items)]:
                print(f"          - @ {f.where}" + (f"  ({f.detail})" if f.detail else ""))
            if not verbose and len(items) > 5:
                print(f"          - ... and {len(items) - 5} more")
    print(f"\nTotal findings: {len(findings)}")


# ---------------------------------------------------------------------------
#  --resolve : single-DET resolution against the trusted-identities file.
#
#  OFFLINE resolution. It makes no
#  network/DNSSEC query. It reports a LAYERED verdict (structure / allow-list /
#  crypto) and never prints a bare "VALID". See identity_resolve.py.
# ---------------------------------------------------------------------------
def _parse_det_arg(s):
    """Accept a DET as 32 hex chars OR the colonful IPv6 form. Returns 16 bytes."""
    s = s.strip()
    if ":" in s:
        return ipaddress.IPv6Address(s).packed
    h = s.replace(" ", "")
    if len(h) != 32:
        raise ValueError(f"DET must be 32 hex chars (16 bytes) or IPv6 form; "
                         f"got {len(h)} chars")
    return bytes.fromhex(h)


def _cmd_resolve(det_arg, anchor_path):
    try:
        import identity_resolve
    except Exception as e:
        print(f"ERROR: --resolve needs identity_resolve.py in this folder: {e}")
        return 2

    try:
        det_bytes = _parse_det_arg(det_arg)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    try:
        trust = identity_resolve.load_trust(anchor_path)
    except FileNotFoundError:
        print(f"ERROR: trusted-identities file not found: {anchor_path}")
        print("       (pass one with --anchor FILE)")
        return 2
    except ValueError as e:
        print(f"ERROR: {anchor_path}: {e}")
        return 2

    r = identity_resolve.resolve_det(det_bytes, trust)
    _print_resolution(r, anchor_path)
    # Exit non-zero if any finding fired (script-friendly), like the main path.
    return 0 if not r.findings else 1


def _print_resolution(r, anchor_path):
    """Human-readable layered verdict for one DET."""
    f = r.fields
    print(f"DET  {r.det_v6()}")
    print(f"     {r.det_hex()}")
    print(f"Trusted-identities file: {anchor_path}")
    print()
    # (a) structural decode — always available, key or no key.
    print("Decoded fields (RFC 9374 3.3):")
    print(f"  prefix : {f['prefix28']:07x}   ({'ok, 2001:30::/28' if r.prefix_ok else 'WRONG'})")
    print(f"  RAA    : {f['raa']}")
    print(f"  HDA    : {f['hda']}")
    print(f"  Suite  : {f['suite']}   ({'EdDSA/cSHAKE128' if f['suite'] == 5 else 'non-standard'})")
    print(f"  hash64 : {f['hash64'].hex().upper()}")
    print(f"  RAA /44 zone : {r.raa_zone}")
    print(f"  HDA /56 zone : {r.hda_zone}")
    print(f"  reverse FQDN : {r.fqdn}")
    print()

    if not r.prefix_ok:
        print("VERDICT: NOT A DET — prefix is not 2001:30::/28 (E-DET-01).")
        _print_findings(r)
        return

    # (b) allow-list, two levels.
    print("Trust (RFC 9886 6 delegation + local allow-list):")
    if r.raa_trusted:
        print(f"  RAA trusted : yes  (RAA {r.raa_trusted['raa']}, "
              f"DET {r.raa_trusted['det'].upper()})")
    else:
        print("  RAA trusted : no")
    if r.hda_trusted:
        print(f"  HDA trusted : yes  -> HDA_TRUSTED level "
              f"(HDA {r.hda_trusted['raa']}/{r.hda_trusted['hda']}, "
              f"DET {r.hda_trusted['det'].upper()})")
    else:
        print("  HDA trusted : no")
    if r.ua_enrolled:
        print("  UA enrolled : yes  -> UA_ENROLLED level "
              "(this exact DET is individually listed)")
    else:
        print("  UA enrolled : no   (not individually listed in 'ua')")
    print()

    # (c) crypto — only if a key is on file.
    print("DET<->key binding (RFC 9374 3.5.2):")
    if r.binding == "VERIFIED":
        print(f"  registered key : {r.registered_key.hex().upper()}")
        print("  binding        : VERIFIED  (key derives this DET)")
    elif r.binding == "MISMATCH":
        print(f"  registered key : {r.registered_key.hex().upper()}")
        print("  binding        : MISMATCH  (key does NOT derive this DET) — E-DET-02")
    else:  # NOT_CHECKED
        print("  registered key : none on file")
        print("  binding        : NOT CHECKED — no key registered for this DET (E-KEY-01)")
    print()

    # One-line plain-English summary, spelling out exactly what held. Never a
    # bare "VALID": the reader must be able to tell structure from crypto.
    claim = f"claims RAA={f['raa']}/HDA={f['hda']}"
    # The nesting clause is read from the resolution rather than asserted. It
    # used to be printed unconditionally on a verified binding, so a DET that
    # had raised E-ZONE-01 was summarised as nesting in the same report.
    nest = "its zones nest" if r.nests else "its zones do NOT nest (E-ZONE-01)"
    if r.binding == "VERIFIED":
        lvl = "individually enrolled" if r.ua_enrolled else "trusted via its HDA"
        print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
              f"({lvl}), {nest}, and its registered key VERIFIES the "
              f"binding.")
    elif r.on_allow_list:
        lvl = "individually enrolled" if r.ua_enrolled else "trusted via its HDA"
        if r.binding == "MISMATCH":
            print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
                  f"({lvl}) and {nest}, BUT the registered key does not "
                  f"derive this DET (binding MISMATCH — E-DET-02).")
        else:
            print(f"SUMMARY: DET {r.det_hex()} {claim}, is on the allow-list "
                  f"({lvl}) and {nest}. No public key is registered for "
                  f"this DET, so the binding was not checked.")
    else:
        print(f"SUMMARY: DET {r.det_hex()} {claim}, but it is NOT on the "
              f"trusted-identities allow-list "
              f"({'zones do not nest either' if not r.nests else 'zones nest, but no trusted entry lists it'}).")

    _print_findings(r)


def _print_findings(r):
    if not r.findings:
        return
    print()
    print("Findings:")
    for eid, detail in r.findings:
        desc = ERROR_CATALOG.get(eid, ("(unknown)", ""))[0]
        print(f"  [{eid}] {desc}")
        if detail:
            print(f"         {detail}")


# ---------------------------------------------------------------------------
#  --dns-lookup : resolve a DET via DNS (PTR->TXT), verify the binding,
#  and offer to write the identity into the trusted-identities file.
#
#  DNSSEC here is PRESENCE-ONLY (mirrors the partner reference); it is reported
#  but never treated as authentication. See identity_lookup.py header.
# ---------------------------------------------------------------------------
def _dns_write_ua_entry(anchor_path, det_bytes, pubkey, reg_status, mfg, sn, model,
                        role=None):
    """Append a resolved identity to the trust file's 'ua' array.

    Returns (ok, message). Refuses to CLOBBER: if the DET is already listed, it
    reports that and does not duplicate. Testable without any I/O prompt.
    """
    import json
    try:
        h = json.load(open(anchor_path, encoding="utf-8"))
    except FileNotFoundError:
        return False, f"trust file not found: {anchor_path}"
    except ValueError as e:
        return False, f"{anchor_path} is not valid JSON: {e}"

    det_hex = det_bytes.hex().upper()
    ua = h.setdefault("ua", [])
    for existing in ua:
        if existing.get("det", "").upper() == det_hex:
            return False, (f"DET {det_hex} is already in {anchor_path} — "
                           f"not modifying it")

    # RAA/HDA are carried in the DET itself (RFC 9374 3.3); record them so the
    # entry is self-describing and the offline nesting check can use them.
    if HAVE_DET:
        f = det.parse_det(det_bytes)
        raa, hda = f["raa"], f["hda"]
    else:
        raa = hda = None

    entry = {"det": det_hex}
    if raa is not None:
        entry["raa"] = raa
        entry["hda"] = hda
    if pubkey is not None:
        entry["public_key"] = pubkey.hex().upper()
    # Provenance travels with the entry, so a later reader can tell a
    # hand-loaded identity from one a DNS answer or an endorsement supplied.
    # reg_status/mfg/sn/model are informational: the trust decision rests on the
    # DET, the key and the nesting.
    if role is None:
        role = f"from DNS ({mfg or '?'} {sn or ''}".strip() + ")"
        if reg_status:
            role += f" reg_status={reg_status}"
    entry["_role"] = role

    ua.append(entry)
    try:
        with open(anchor_path, "w", encoding="utf-8") as fh:
            json.dump(h, fh, indent=2)
            fh.write("\n")
    except OSError as e:
        return False, f"could not write {anchor_path}: {e}"
    return True, f"wrote DET {det_hex} into {anchor_path} 'ua' array"


def _cmd_dns_lookup(det_arg, anchor_path, dns_server):
    try:
        import identity_lookup
    except Exception as e:
        print(f"ERROR: --dns-lookup needs identity_lookup.py in this folder: {e}")
        return 2

    try:
        det_bytes = _parse_det_arg(det_arg)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    server = dns_server or identity_lookup.DEFAULT_DNS_SERVER
    print(f"DNS lookup for DET {det_bytes.hex().upper()}")
    print(f"  resolver: {server}")
    try:
        resolver = identity_lookup.DnsPythonResolver(server=server)
    except RuntimeError as e:
        print(f"ERROR: {e}")
        print("       Install it with:  pip install dnspython")
        return 2

    r = identity_lookup.lookup_det(det_bytes, resolver)
    return _finish_dns_lookup(r, anchor_path)


def _finish_dns_lookup(r, anchor_path):
    """Shared print + interactive-write path (also used by the mock tests)."""
    print(f"  DET   : {r.det_v6()}")
    if r.error and r.fqdn is None:
        print(f"  RESULT: lookup failed — {r.error}")
        return 1

    print(f"  FQDN  : {r.fqdn}")
    print()
    print("  TXT record:")
    print(f"    mfg        : {r.mfg}")
    print(f"    sn         : {r.sn}")
    print(f"    model      : {r.model}")
    print(f"    reg_status : {r.reg_status}")
    print(f"    pubkey     : {r.pubkey_b64}"
          f"{'' if not r.pubkey else '  (' + str(len(r.pubkey)) + ' bytes)'}")
    print()

    # DNSSEC — presence only, stated honestly.
    if r.dnssec_present:
        print("  DNSSEC : RRSIG present — NOT validated (presence-only; see docs)")
    else:
        print("  DNSSEC : no RRSIG in answer")

    # Binding — the check that actually matters for trust.
    if r.error:
        print(f"  BINDING: not checked — {r.error}")
    elif r.binding_ok is None:
        print("  BINDING: not checked — det.py unavailable")
    elif r.binding_ok:
        print("  BINDING: VERIFIED — the DNS key derives this DET (RFC 9374 3.5.2)")
    else:
        print("  BINDING: FAILED — the DNS key does NOT derive this DET (E-DET-02)")
    print()

    # Offer to write — but only when it is safe to.
    if r.binding_ok is not True:
        print("Not offering to save: the DET<->key binding did not verify, so "
              "this identity is not trustworthy. Nothing written.")
        return 1

    try:
        ans = input(f"Write this identity into {anchor_path}'s 'ua' array? [y/N] ")
    except EOFError:
        ans = ""
    if ans.strip().lower() in ("y", "yes"):
        ok, msg = _dns_write_ua_entry(anchor_path, r.det, r.pubkey,
                                      r.reg_status, r.mfg, r.sn, r.model)
        print(("OK: " if ok else "NOT WRITTEN: ") + msg)
        if ok:
            # Post-write coherence: re-load via the resolver and confirm it
            # parses and nests, so a bad append is caught immediately.
            try:
                import identity_resolve
                trust = identity_resolve.load_trust(anchor_path)
                res = identity_resolve.resolve_det(r.det, trust)
                if res.nests:
                    print("     verified: file still parses and the DET nests.")
                else:
                    print("     WARNING: written, but the DET does not nest under "
                          "a trusted RAA/HDA zone (E-ZONE-01). Check the file.")
            except Exception as e:
                print(f"     WARNING: could not re-verify the file: {e}")
        return 0 if ok else 1
    else:
        print("Not written.")
        return 0


def _offer_trust(keys, anchor_path):
    """Ask, per identity learned from the air, whether to persist it.

    THERE IS NO AUTOMATIC WRITE PATH. A key learned from an endorsement is held
    for the current run and nothing else, and it reaches the trusted-identities
    file only through an answer given here. Persisting one changes what a later
    run will accept with no evidence on the air at all, so it is a decision the
    operator takes explicitly or not at all.
    """
    import sys as _sys
    learned = [(d, o) for d, o in keys.origins().items() if o.source == SRC_AIR]
    if not learned:
        return
    print()
    print(f"Identities learned from endorsements this run: {len(learned)}")
    if not _sys.stdin.isatty():
        print("  (not a terminal: nothing was written, and nothing was asked)")
        return
    for d, o in learned:
        pub = keys.for_det(d)
        print()
        print(f"  DET    {_det_str(d)}")
        print(f"  key    {pub.hex().upper()}")
        print(f"  source {o.label()}")
        try:
            ans = input(f"  [w]rite into {anchor_path}, or keep it for this run "
                        f"only? [w/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans in ("w", "write", "y", "yes"):
            ok, msg = _dns_write_ua_entry(
                anchor_path, d, pub, "", "", "", "",
                role=f"learned from an endorsement by {_det_str(o.parent_det)}"
                     if o.parent_det else "learned from an endorsement")
            print(f"  {msg}")
        else:
            print("  kept for this run only.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Offline DRIP/ASTM observer")
    ap.add_argument("file", nargs="?",
                    help="capture file - Format L (ESP32 serial log), "
                         "A (DRIP_Sniffer air capture), BT (DRIP_Sniffer Bluetooth "
                         "Legacy capture, also mixed with A), W (Wireshark bytes) "
                         "or B (flat hex). Optional with --list-keys.")
    ap.add_argument("--pubkey", metavar="HEX",
                    help="32-byte Ed25519 public key (hex). Used for any DET that has no "
                         "keyring entry -- i.e. a single unknown drone.")
    ap.add_argument("--keyring", metavar="FILE",
                    help="file of 'DET_HEX PUBKEY_HEX' pairs, one per line ('#' comments "
                         "allowed). Adds to / overrides the built-in bench identities.")
    ap.add_argument("--no-builtin-keys", action="store_true",
                    help="do not preload the 3 known bench identities (slots 0-2)")
    ap.add_argument("--list-keys", action="store_true",
                    help="print the keyring and exit")
    ap.add_argument("--resolve", metavar="DET",
                    help="resolve a single DET (32 hex chars, or the colonful "
                         "IPv6 form) against the trusted-identities file "
                         "(--anchor, default hierarchy.json) and exit. Offline: "
                         "decodes the DET, checks zone nesting and allow-list "
                         "membership, and verifies the DET<->key binding IF a "
                         "key is on file. Does NOT touch the network.")
    ap.add_argument("--dns-lookup", metavar="DET",
                    help="look up a DET in DNS (PTR->TXT) via the partner "
                         "resolver, verify the DET<->key binding, and offer to "
                         "write the identity into the trusted-identities file "
                         "(--anchor). NEEDS NETWORK + dnspython.")
    ap.add_argument("--dns-server", metavar="IP", default=None,
                    help="resolver for --dns-lookup (default 141.227.148.117, "
                         "the partner's driplab.example server).")
    ap.add_argument("--dns-fallback", action="store_true",
                    help="while reading a capture, when a DET is NOT in the "
                         "trusted-identities file, look it up in DNS once, show "
                         "it, and offer to add it (writes to --anchor on yes). "
                         "One DNS query per untrusted DET per run. Needs network "
                         "+ dnspython. Off by default.")
    ap.add_argument("--offer-trust", action="store_true",
                    help="after the run, list every identity whose key was "
                         "learned from an endorsement received on the air and "
                         "ask, one by one, whether to write it into the "
                         "trusted-identities file (--anchor) or to keep it for "
                         "this run only. Without this flag an air-learned key "
                         "is never persisted: there is no automatic write path.")
    ap.add_argument("--anchor", metavar="FILE", default="hierarchy.json",
                    help="hierarchy.json holding the trust anchor (Apex DET + "
                         "public key). Absent = use the built-in bench anchor. "
                         "Swap in a real DNSSEC-anchored Apex here.")
    ap.add_argument("--pure-python", action="store_true",
                    help="force the ed25519.py reference implementation "
                         "(~1300x slower; use to cross-check a result)")
    ap.add_argument("--now", type=int, help="reference Unix time for freshness check")
    ap.add_argument("--max-age", type=int, help="max allowed |age| in seconds (with --now)")
    ap.add_argument("--verbose", action="store_true", help="print every decoded item")
    args = ap.parse_args(argv)

    # ---- build the keyring (single source of truth: the anchor file) -------
    # --no-builtin-keys now means "do not load the trusted-identities file";
    # only --keyring / --pubkey supply keys. Kept for the same use as before.
    keys = Keyring() if args.no_builtin_keys else default_keyring(args.anchor)

    if args.pubkey:
        if not HAVE_DET:
            print("ERROR: --pubkey was supplied but det.py could not be imported.")
            print("       Place det.py in the same folder as observer.py and retry.")
            return 2
        hexkey = args.pubkey.strip()
        if len(hexkey) != 64:
            print(f"ERROR: --pubkey must be 64 hex chars (32 bytes); got {len(hexkey)} chars.")
            return 2
        try:
            keys.set_wildcard(bytes.fromhex(hexkey))
        except ValueError as e:
            print(f"ERROR: --pubkey is not valid hex: {e}")
            return 2

    if args.keyring:
        try:
            with open(args.keyring, encoding="utf-8") as fh:
                for ln, line in enumerate(fh, 1):
                    t = line.split("#", 1)[0].split()
                    if not t:
                        continue
                    if len(t) != 2:
                        print(f"ERROR: {args.keyring}:{ln}: expected 'DET_HEX PUBKEY_HEX'")
                        return 2
                    d_hex, p_hex = t
                    if len(d_hex) != 32 or len(p_hex) != 64:
                        print(f"ERROR: {args.keyring}:{ln}: DET must be 32 hex chars "
                              f"and pubkey 64; got {len(d_hex)}/{len(p_hex)}")
                        return 2
                    try:
                        keys.add(bytes.fromhex(d_hex), bytes.fromhex(p_hex),
                                 source=SRC_CLI, note=args.keyring)
                    except BindingRefused as e:
                        print(f"ERROR: {args.keyring}:{ln}: {e}")
                        return 2
        except OSError as e:
            print(f"ERROR: cannot read --keyring: {e}")
            return 2

    if args.resolve:
        return _cmd_resolve(args.resolve, args.anchor)

    if args.dns_lookup:
        return _cmd_dns_lookup(args.dns_lookup, args.anchor, args.dns_server)

    if args.list_keys:
        print(f"Keyring: {len(keys)} DET-bound key(s)"
              f"{' + 1 wildcard (--pubkey)' if keys.for_det(None) else ''}")
        # Labels come from the trusted-identities file (single source of truth).
        labels = {}
        try:
            import identity_resolve
            trust = identity_resolve.load_trust(args.anchor)
            for d_hex, _p, lbl in identity_resolve.iter_known_keys(trust):
                labels[bytes.fromhex(d_hex)] = lbl
        except Exception:
            pass
        for d in keys._by_det:
            lbl = labels.get(d, "(from --keyring)")
            print(f"  {_det_str(d):40s}  {lbl}")
            print(f"    key {keys.for_det(d).hex().upper()}")
        if keys.for_det(None):
            print(f"  {'(any other DET)':40s}  wildcard from --pubkey")
        return 0

    if not args.file:
        print("ERROR: no capture file given. (A file is optional only with --list-keys.)")
        return 2

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    # Trust anchor first: everything downstream is verified against it.
    if ANCHOR_SELFTEST:
        print(f"WARNING: {ANCHOR_SELFTEST}")
    try:
        if load_hierarchy(args.anchor):
            print(f"Trust anchor: {ANCHOR_SOURCE}  "
                  f"apex={_det_str(APEX_DET)}")
        elif args.anchor != "hierarchy.json":
            print(f"ERROR: --anchor {args.anchor}: file not found")
            return 2
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2

    if args.pure_python and HAVE_ED:
        ed25519_backend.force_pure_python()
    if HAVE_ED:
        print(f"Ed25519 backend: {ed25519_backend.backend_name()}")
        print(f"  self-test: {ed25519_backend.selftest_note()}")

    # Arm the once-per-DET DNS fallback if requested.
    dns_fb = None
    if args.dns_fallback:
        import sys as _sys
        server = args.dns_server or None
        try:
            import identity_lookup
            server = server or identity_lookup.DEFAULT_DNS_SERVER
        except Exception:
            pass
        dns_fb = DnsFallback(keys, args.anchor, server,
                             interactive=_sys.stdin.isatty())
        keys.fallback = dns_fb

    # The same DNS fallback that resolves an unknown UA also resolves an
    # unknown parent during the endorsement walk, which is what lets the
    # registry supply an Apex, RAA or HDA anchor the capture never carried.
    resolver = dns_fb.resolve_parent if dns_fb is not None else None

    try:
        fmt, report, findings = run(text, keys=keys, now=args.now,
                                    max_age=args.max_age, progress=True,
                                    resolver=resolver)
    except UnknownFormatError as e:
        # Refuse rather than guess. See run()'s docstring.
        print(f"ERROR: {e}")
        return 2
    print_report(fmt, report, findings, verbose=args.verbose, keys=keys)
    if dns_fb is not None:
        dns_fb.report()
    if args.offer_trust:
        _offer_trust(keys, args.anchor)
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
