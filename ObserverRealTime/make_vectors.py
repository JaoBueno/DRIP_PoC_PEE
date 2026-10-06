#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - make_vectors.py
#  A small REFERENCE ENCODER that hand-builds ASTM/DRIP messages (valid and
#  deliberately broken) directly from the spec layouts. It does two jobs:
#    1. Writes a Format B test file (--write vectors.txt).
#    2. Self-tests the observer (--selftest): runs observer.run() on the
#       built-in vectors and asserts each broken vector raises exactly the
#       expected error ID, and the valid vectors raise none.
#
#  This is the reference the ESP32 generator must match byte for byte.
#
#  The vectors are of three kinds: structural ones built from the ASTM layouts,
#  cryptographically signed DRIP Wrapper, Link and Manifest payloads built with
#  real Ed25519 signatures, and the trust-model cases of trust_self_test(),
#  which check what the observer accepts rather than what it decodes.
# =============================================================================

import sys
import struct
import argparse

import odid
import observer

# The test identity, taken from det.py so both sides use one value.
try:
    import det
    UA_DET = det.UA_DET
    UA_PUB = det.UA_PUB
except Exception:                                  # fallback to recorded values
    UA_DET = bytes.fromhex("20010030fa07d0054dfdc31103e51953")
    UA_PUB = None

# Ed25519 private seed for signing valid Wrapper vectors (matches UA_PUB / on-device UA_PRIV_SEED)
try:
    import ed25519
    UA_PRIV_SEED = bytes.fromhex("568BF5E8F08ABAADB68BA1964BC25F2976A8AFC938244A39F76E0AB0C703CCD6")
    HAVE_ED = True
except Exception:
    HAVE_ED = False

VER = 0x2
def _hdr(t): return bytes([(t << 4) | VER])


# ---------------------------------------------------------------------------
#  Message builders (each returns exactly 25 bytes)
# ---------------------------------------------------------------------------
def basic_id(det_bytes=UA_DET, ua_type=0, id_type=4, ssi_type=1, version=VER):
    b = bytes([(0x0 << 4) | version]) + bytes([(id_type << 4) | ua_type])
    uasid = bytes([ssi_type]) + det_bytes              # SSI Type + 16-byte DET
    uasid += b'\x00' * (20 - len(uasid))
    b += uasid + b'\x00' * 3
    assert len(b) == 25
    return b


def self_id(text="DronesRus:Survey", dtype=0):
    d = text.encode()[:23]
    d += b'\x00' * (23 - len(d))
    b = _hdr(0x3) + bytes([dtype]) + d
    assert len(b) == 25
    return b


def operator_id(text="OPERATOR-TEST-01", otype=0):
    o = text.encode()[:20]
    o += b'\x00' * (20 - len(o))
    b = _hdr(0x5) + bytes([otype]) + o + b'\x00' * 3
    assert len(b) == 25
    return b


def system_msg(lat=-23.2237, lon=-45.9009, ts=0x0A1B2C3D):
    b = _hdr(0x4) + bytes([0x00])
    b += struct.pack('<i', int(lat * 1e7)) + struct.pack('<i', int(lon * 1e7))
    b += struct.pack('<H', 1)                           # area count
    b += bytes([0])                                     # area radius
    b += struct.pack('<H', 0) + struct.pack('<H', 0)    # ceiling, floor
    b += bytes([0])                                     # UA classification
    b += struct.pack('<H', 0)                           # operator altitude
    b += struct.pack('<I', ts)                          # timestamp
    b += bytes([0])                                     # reserved
    assert len(b) == 25
    return b


def auth_page0(sam_type, sam_payload, last_page, ts=0x0A1B2C3D,
               auth_type=5, data_page=0, reserved_nibble=0, length_override=None):
    """Page 0 of an Authentication message.

    `length_override` writes a Length field that disagrees with the payload
    actually paged, which is the only way to reach E-AUTH-05 without also
    breaking the page numbering and raising E-AUTH-03.
    """
    auth_data = bytes([sam_type]) + sam_payload         # first auth byte = SAM Type
    b = _hdr(0x2) + bytes([(auth_type << 4) | data_page])
    b += bytes([(reserved_nibble << 4) | (last_page & 0xF)])
    declared = len(auth_data) if length_override is None else length_override
    b += bytes([declared & 0xFF])
    b += struct.pack('<I', ts & 0xFFFFFFFF)
    page0 = auth_data[:17]
    page0 += b'\x00' * (17 - len(page0))
    b += page0
    assert len(b) == 25
    return b, auth_data


def auth_pageN(auth_data, idx_into_data, page, auth_type=5):
    c = auth_data[idx_into_data:idx_into_data + 23]
    c += b'\x00' * (23 - len(c))
    b = _hdr(0x2) + bytes([(auth_type << 4) | (page & 0xF)]) + c
    assert len(b) == 25
    return b


def pack(msgs, msg_size=0x19, count=None):
    n = len(msgs) if count is None else count
    b = _hdr(0xF) + bytes([msg_size, n])
    for m in msgs:
        b += m
    return b


def _location_msg():
    """A minimal, valid 25-byte Location/Vector message (type 0x1). Field
       content is not decoded by the signature check, so a placeholder body is
       fine for the crypto self-test (both signer and verifier see the same
       raw bytes)."""
    b = _hdr(0x1) + bytes(24)
    assert len(b) == 25
    return b


def build_extended_wrapper_pages(astm_msgs, det_bytes, vnb, vna, priv_seed):
    """Build the 5 Auth pages of an Extended Transport DRIP Wrapper that signs
       over `astm_msgs`, mirroring the firmware (drip_auth.cpp) exactly:
         Evidence = astm_msgs stable-sorted ascending by type
         signed   = VNB(4,LE) || VNA(4,LE) || Evidence || DET(16)
         wire     = SAM(0x02) || VNB(4) || VNA(4) || DET(16) || Sig(64)  (89 B)
       Returns (pages[5], signed_bytes)."""
    ordered = sorted(astm_msgs, key=lambda m: (m[0] >> 4) & 0xF)   # stable sort
    evidence = b"".join(ordered)
    signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + evidence + det_bytes
    sig = ed25519.sign(priv_seed, signed)
    sam_payload = struct.pack('<I', vnb) + struct.pack('<I', vna) + det_bytes + sig  # 88 B (after SAM type)
    p0, authdata = auth_page0(0x02, sam_payload, last_page=4, ts=vnb)               # 89 B total -> 5 pages
    pages = [p0]
    off = 17
    for pg in range(1, 5):
        pages.append(auth_pageN(authdata, off, pg))
        off += 23
    return pages, signed


# ---------------------------------------------------------------------------
#  Vector set: (label, record_bytes, expected_error_id_or_None, needs_pubkey)
# ---------------------------------------------------------------------------
def build_vectors():
    V = []

    # ---- valid -------------------------------------------------------------
    # Placeholder Wrapper (SAM 0x02, no real signature): STRUCTURAL test only,
    # so run without a pubkey (E-SIG-01/E-DET-02 require a key and are skipped).
    a0_ok, _ = auth_page0(0x02, b'\x00' * 8, last_page=0)
    valid_pack = pack([basic_id(), system_msg(), self_id(), operator_id(), a0_ok])
    V.append(("valid pack (structural, placeholder Wrapper)", valid_pack, None, False))
    V.append(("valid single Basic ID (our DET)", basic_id(), None, True))

    # a valid 2-page auth, reassembles cleanly
    a0_2, ad2 = auth_page0(0x02, bytes(range(0x10, 0x37)), last_page=1)   # 39-byte payload
    a1_2 = auth_pageN(ad2, 17, 1)
    V.append(("valid 2-page Wrapper auth (structural)", pack([basic_id(), a0_2, a1_2]), None, False))

    # ---- broken (one error each) ------------------------------------------
    V.append(("E-FMT-02 wrong version", basic_id(version=0x3), "E-FMT-02", False))
    V.append(("E-PACK-01 size!=0x19", pack([basic_id()], msg_size=0x18), "E-PACK-01", False))
    V.append(("E-PACK-02 count=0", pack([], count=0), "E-PACK-02", False))
    V.append(("E-PACK-03 truncated", pack([basic_id(), self_id()], count=3), "E-PACK-03", False))
    V.append(("E-PACK-04 nested pack", pack([pack([basic_id()], count=1)[:25]]), "E-PACK-04", False))
    a0_at7, _ = auth_page0(0x00, b'\x00' * 4, last_page=0, auth_type=7)
    V.append(("E-AUTH-01 reserved AuthType 7", pack([a0_at7]), "E-AUTH-01", False))
    a0_rsv, _ = auth_page0(0x02, b'\x00' * 4, last_page=0, reserved_nibble=0x1)
    V.append(("E-AUTH-04 last-page reserved bits", pack([a0_rsv]), "E-AUTH-04", False))
    # auth claims last page 2 but page 1 is missing -> E-AUTH-03 (+E-AUTH-05)
    a0_gap, _ = auth_page0(0x02, b'\x00' * 40, last_page=2)
    V.append(("E-AUTH-03 page gap", pack([a0_gap]), "E-AUTH-03", False))
    a0_sam9, _ = auth_page0(0x09, b'\x00' * 4, last_page=0)   # SAM type 0x09 unknown
    V.append(("E-SAM-01 unknown SAM type", pack([a0_sam9]), "E-SAM-01", False))
    # DET with a non-DET prefix (flip the top byte of the prefix)
    bad_prefix_det = bytes([0x30]) + UA_DET[1:]
    V.append(("E-DET-01 bad DET prefix", basic_id(det_bytes=bad_prefix_det), "E-DET-01", False))
    # valid prefix DET but corrupted hash -> binding fails (needs pubkey)
    bad_hash_det = UA_DET[:8] + bytes([UA_DET[8] ^ 0x01]) + UA_DET[9:]
    V.append(("E-DET-02 binding failure", basic_id(det_bytes=bad_hash_det), "E-DET-02", True))

    # ---- the six codes that previously had no vector -----------------------
    # Each existed in the catalogue with a governing clause, and the encoder
    # built nothing that reached it. A code with no vector is an assertion about
    # the observer that nothing checks.

    # E-FMT-01: message type 0x6 is outside the assigned set (ASTM Table 3,
    # valid 0x0-0x5 and 0xF).
    V.append(("E-FMT-01 unknown message type", _hdr(0x6) + bytes(24), "E-FMT-01", False))

    # E-FMT-03: a record that is not 25 bytes. The leading nibble is not 0xF, so
    # it is read as a single message rather than as a pack (ASTM 5.4.5.4).
    V.append(("E-FMT-03 record shorter than 25 bytes",
              _hdr(0x0) + bytes(19), "E-FMT-03", False))

    # E-AUTH-02: a continuation page with no page 0 in front of it. Table 8
    # requires the page number of a page-0 message to be 0.
    orphan = auth_pageN(bytes(23), 0, page=1)
    V.append(("E-AUTH-02 page 1 with no page 0",
              pack([basic_id(), orphan]), "E-AUTH-02", False))

    # E-AUTH-05: two pages carrying 40 octets while the Length field declares
    # 60. The page numbering is correct, so E-AUTH-03 does not fire and the
    # length inconsistency is isolated (ASTM 5.4.5.15).
    a0_len, ad_len = auth_page0(0x02, bytes(38), last_page=1, length_override=60)
    a1_len = auth_pageN(ad_len, 17, 1)
    V.append(("E-AUTH-05 length disagrees with pages",
              pack([basic_id(), a0_len, a1_len]), "E-AUTH-05", False))

    # E-AUTH-06: a timestamp past the Table 8 limitation of 01/19/2087, which
    # is 2^31-1 seconds after the 2019 epoch.
    a0_ts, _ = auth_page0(0x02, b'\x00' * 8, last_page=0, ts=0x80000000)
    V.append(("E-AUTH-06 timestamp past the Table 8 ceiling",
              pack([basic_id(), a0_ts]), "E-AUTH-06", False))

    # E-SEM-01: DRIP authentication present with no DRIP Basic ID in the same
    # pack, so nothing in the pack says which DET the evidence belongs to.
    a0_sem, _ = auth_page0(0x02, b'\x00' * 8, last_page=0)
    V.append(("E-SEM-01 DRIP auth with no DRIP Basic ID",
              pack([self_id(), a0_sem]), "E-SEM-01", False))

    # ---- signed Extended Wrapper (E-SIG-01) --------------------------------
    if HAVE_ED and UA_PUB is not None:
        vnb = 0x0A1B2C3D
        vna = vnb + 120
        astm = [basic_id(), system_msg(), _location_msg()]   # types 0x0, 0x4, 0x1
        pages, _signed = build_extended_wrapper_pages(astm, UA_DET, vnb, vna, UA_PRIV_SEED)
        # A valid Wrapper pack: the SAME ASTM messages the signature covers + 5 wrapper pages.
        good = pack([basic_id(), _location_msg(), system_msg()] + pages)
        V.append(("valid signed Extended Wrapper", good, None, True))
        # Corrupt the first signature byte (authdata[25] -> page 1, offset 10) -> E-SIG-01
        bad_pages = [bytearray(p) for p in pages]
        bad_pages[1][10] ^= 0x01
        bad = pack([basic_id(), _location_msg(), system_msg()] + [bytes(p) for p in bad_pages])
        V.append(("E-SIG-01 corrupted Wrapper signature", bad, "E-SIG-01", True))

    return V


# ---------------------------------------------------------------------------
#  Output + self-test
# ---------------------------------------------------------------------------
def to_format_b(vectors):
    lines = ["# DRIP Observer test vectors (Format B). Auto-generated by make_vectors.py",
             "# Each line is hex; '# expect: <ID>' tags the following record.", ""]
    for label, rec, expect, _needs in vectors:
        lines.append(f"# {label}")
        if expect:
            lines.append(f"# expect: {expect}")
        lines.append(' '.join(f'{x:02X}' for x in rec))
        lines.append("")
    return "\n".join(lines)


def self_test():
    vectors = build_vectors()
    passed = failed = 0
    for label, rec, expect, needs_pub in vectors:
        pub = UA_PUB if needs_pub else None
        text = ' '.join(f'{x:02X}' for x in rec)
        _fmt, _report, findings = observer.run(text, pub=pub)
        ids = {f.error_id for f in findings}
        if expect is None:
            ok = (len(findings) == 0)
        else:
            ok = (expect in ids)
        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1
        detail = "no findings" if not findings else ", ".join(sorted(ids))
        print(f"  [{status}] {label:42s} expect={expect or '(clean)':10s} got: {detail}")
    print(f"\nself-test: {passed} passed, {failed} failed")
    chain_ok = man_ok = trust_ok = legacy_ok = True
    if HAVE_ED:
        chain_ok = chain_self_test()
        man_ok = manifest_self_test()
        trust_ok = trust_self_test()
        legacy_ok = legacy_self_test()          # session 3: Bluetooth Legacy / FEC
    return failed == 0 and chain_ok and man_ok and trust_ok and legacy_ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="DRIP reference encoder / observer self-test")
    ap.add_argument("--write", metavar="FILE", help="write the vectors as a Format B file")
    ap.add_argument("--selftest", action="store_true", help="run the observer self-test")
    args = ap.parse_args(argv)

    if args.write:
        with open(args.write, "w") as fh:
            fh.write(to_format_b(build_vectors()))
        print(f"wrote {args.write}")
    if args.selftest or not args.write:
        ok = self_test()
        return 0 if ok else 1
    return 0



# ===========================================================================
#  DRIP Link chain of trust vectors: fabricates the same 3-link
#  Broadcast Endorsement chain that drip_registration.cpp builds, with REAL
#  Ed25519 signatures by the test parent keys, then pages each BE into a Link
#  pack. Used to self-test the observer's verify_link_chain().
# ===========================================================================
if HAVE_ED:
    _APEX_SEED = bytes(range(0xA0, 0xC0))
    _RAA_SEED  = bytes(range(0xC0, 0xE0))
    _HDA_SEED  = bytes(range(0xE0, 0x100))
    _APEX_RAA, _APEX_HDA = 0x0000, 0x0000
    _RAA_RAA,  _RAA_HDA  = 0x0001, 0x0000
    _HDA_RAA,  _HDA_HDA  = 0x0001, 0x0001

    def _mk_be(vnb, vna, det_child, hi_child, det_parent, parent_seed):
        signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + det_child + hi_child + det_parent
        return {"vnb": vnb, "vna": vna, "det_child": det_child, "hi_child": hi_child,
                "det_parent": det_parent, "sig": ed25519.sign(parent_seed, signed)}

    def _be_to_pages(be):
        payload = (struct.pack('<I', be['vnb']) + struct.pack('<I', be['vna'])
                   + be['det_child'] + be['hi_child'] + be['det_parent'] + be['sig'])  # 136 B
        p0, authdata = auth_page0(0x01, payload, last_page=6, ts=be['vnb'])              # 137 B -> 7 pages
        pages = [p0]; off = 17
        for pg in range(1, 7):
            pages.append(auth_pageN(authdata, off, pg)); off += 23
        return pages

    def _be_pack(be, bid_det=None):
        """A pack carrying one endorsement. `bid_det` sets the DET in the Basic
           ID, which must be the endorsed child whenever the vector is about a
           DET other than the default test identity."""
        bid = basic_id() if bid_det is None else basic_id(bid_det)
        return pack([bid, _location_msg()] + _be_to_pages(be))

    def build_chain(vnb=201699200, vna=None):
        if vna is None: vna = vnb + 86400
        apex_hi = ed25519.derive_pubkey(_APEX_SEED)
        raa_hi  = ed25519.derive_pubkey(_RAA_SEED)
        hda_hi  = ed25519.derive_pubkey(_HDA_SEED)
        apex_det = det.compute_det(apex_hi, _APEX_RAA, _APEX_HDA, 5)
        raa_det  = det.compute_det(raa_hi,  _RAA_RAA,  _RAA_HDA,  5)
        hda_det  = det.compute_det(hda_hi,  _HDA_RAA,  _HDA_HDA,  5)
        return {
            "apex_raa": _mk_be(vnb, vna, raa_det, raa_hi, apex_det, _APEX_SEED),
            "raa_hda":  _mk_be(vnb, vna, hda_det, hda_hi, raa_det,  _RAA_SEED),
            "hda_ua":   _mk_be(vnb, vna, UA_DET,  UA_PUB, hda_det,  _HDA_SEED),
            "hda_det":  hda_det,
        }

    def _packs_text(bes):
        return "\n".join(' '.join(f'{x:02X}' for x in _be_pack(b)) for b in bes)

    def chain_self_test():
        print("\n--- DRIP Link chain self-test ---")
        passed = failed = 0
        def check(label, bes, expect, now=None):
            nonlocal passed, failed
            _f, _r, findings = observer.run(_packs_text(bes), now=now)
            ids = {f.error_id for f in findings}
            ok = (expect is None and not findings) or (expect is not None and expect in ids)
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:38s} expect={expect or '(clean)':10s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}")
            passed += ok; failed += (not ok)

        c = build_chain()
        check("valid full 3-link chain", [c['apex_raa'], c['raa_hda'], c['hda_ua']], None)

        # E-LINK-02: corrupt one signature byte in the RAA,HDA endorsement
        bad = dict(c['raa_hda']); bad['sig'] = bytes([bad['sig'][0] ^ 1]) + bad['sig'][1:]
        check("E-LINK-02 bad parent signature", [c['apex_raa'], bad, c['hda_ua']], "E-LINK-02")

        # E-LINK-03: omit the Apex,RAA link -> RAA,HDA has no path to anchor
        check("E-LINK-03 broken chain (no Apex)", [c['raa_hda'], c['hda_ua']], "E-LINK-03")

        # E-LINK-01: leaf child DET hash corrupted but re-signed (binding fails, sig valid)
        bad_det = UA_DET[:8] + bytes([UA_DET[8] ^ 1]) + UA_DET[9:]
        leaf_bad = _mk_be(c['hda_ua']['vnb'], c['hda_ua']['vna'], bad_det, UA_PUB,
                          c['hda_det'], _HDA_SEED)
        check("E-LINK-01 child DET/HI mismatch", [c['apex_raa'], c['raa_hda'], leaf_bad], "E-LINK-01")

        # E-LINK-04: valid chain, but the reference time is after VNA.
        # `now` is a UNIX timestamp, so the DRIP-epoch VNA is converted before
        # use. Passing the raw DRIP value put the reference time in 1971, which
        # is before every VNB, so the check fired for the opposite reason to the
        # one the label claims.
        check("E-LINK-04 expired window", [c['apex_raa'], c['raa_hda'], c['hda_ua']],
              "E-LINK-04", now=odid.EPOCH_2019 + c['hda_ua']['vna'] + 10)

        print(f"  chain self-test: {passed} passed, {failed} failed")
        return failed == 0


# ===========================================================================
#  DRIP Manifest vectors: fabricates a Manifest that
#  references a Wrapper pack hash and a BE:HDA,UA link hash, exactly as the
#  firmware (drip_manifest.cpp) does, and self-tests verify_manifests().
# ===========================================================================
if HAVE_ED:
    import math as _math

    def _page_sam(sam_type, sam_payload, ts):
        total = 1 + len(sam_payload)
        n = (_math.ceil((total - 17) / 23) + 1) if total > 17 else 1
        p0, authdata = auth_page0(sam_type, sam_payload, last_page=n - 1, ts=ts)
        pages = [p0]; off = 17
        for pg in range(1, n):
            pages.append(auth_pageN(authdata, off, pg)); off += 23
        return pages

    def _be_full_sam(be):
        return (bytes([0x01]) + struct.pack('<I', be['vnb']) + struct.pack('<I', be['vna'])
                + be['det_child'] + be['hi_child'] + be['det_parent'] + be['sig'])

    def _manifest_payload(prev8, link_hash8, pack_hashes, vnb, vna,
                          ua_det=UA_DET, ua_seed=UA_PRIV_SEED, force_curr=None, break_sig=False):
        astm = b"".join(pack_hashes)
        ev = bytearray(prev8 + b"\x00" * 8 + link_hash8 + astm)
        curr = det.cshake128(bytes(ev), 8, N=b'', S=b"Remote ID Auth Hash")
        ev[8:16] = force_curr if force_curr is not None else curr
        signed = struct.pack('<I', vnb) + struct.pack('<I', vna) + bytes(ev) + ua_det
        sig = bytearray(ed25519.sign(ua_seed, signed))
        if break_sig:
            sig[0] ^= 0x01
        payload = struct.pack('<I', vnb) + struct.pack('<I', vna) + bytes(ev) + ua_det + bytes(sig)
        return payload, bytes(curr)

    def _manifest_pack(payload, vnb):
        return pack([basic_id(), _location_msg(), system_msg()] + _page_sam(0x03, payload, vnb))

    def manifest_self_test():
        print("\n--- DRIP Manifest self-test ---")
        passed = failed = 0
        vnb = 201699200; vna = vnb + 120

        wp, _ = build_extended_wrapper_pages([basic_id(), system_msg(), _location_msg()],
                                             UA_DET, vnb, vna, UA_PRIV_SEED)
        wrapper_pack = pack([basic_id(), _location_msg(), system_msg()] + wp)
        pack_hash = det.cshake128(wrapper_pack, 8, N=b'', S=b"Remote ID Auth Hash")

        c = build_chain(vnb, vna)
        link_pack = _be_pack(c['hda_ua'])
        link_hash = det.cshake128(_be_full_sam(c['hda_ua']), 8, N=b'', S=b"Remote ID Auth Hash")

        prev0 = bytes(8)  # first manifest seed (zeros for reproducibility)
        pl, curr1 = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna)
        man_pack = _manifest_pack(pl, vnb)
        chain_packs = [_be_pack(c['apex_raa']), _be_pack(c['raa_hda']), link_pack]

        def check(label, packs_list, expect, now=None):
            nonlocal passed, failed
            text = "\n".join(' '.join(f'{x:02X}' for x in p) for p in packs_list)
            _f, _r, findings = observer.run(text, pub=UA_PUB, now=now)
            ids = {f.error_id for f in findings}
            ok = (expect is None and not findings) or (expect is not None and expect in ids)
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:40s} expect={expect or '(clean)':10s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}")
            passed += ok; failed += (not ok)

        check("valid manifest (all refs present)", [wrapper_pack] + chain_packs + [man_pack], None)
        check("E-MAN-02 pack hash not observed", chain_packs + [man_pack], "E-MAN-02")
        check("E-MAN-03 link hash not observed",
              [wrapper_pack, _be_pack(c['apex_raa']), _be_pack(c['raa_hda']), man_pack], "E-MAN-03")

        pl_sig, _ = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna, break_sig=True)
        check("E-MAN-01 bad signature", [wrapper_pack] + chain_packs + [_manifest_pack(pl_sig, vnb)], "E-MAN-01")

        pl_curr, _ = _manifest_payload(prev0, link_hash, [pack_hash], vnb, vna, force_curr=bytes(8))
        check("E-MAN-05 wrong current hash", [wrapper_pack] + chain_packs + [_manifest_pack(pl_curr, vnb)], "E-MAN-05")

        # E-MAN-04: two manifests where the 2nd Prev != 1st Curr
        pl2, _ = _manifest_payload(bytes([0xAA]) * 8, link_hash, [pack_hash], vnb + 1, vna + 1)
        check("E-MAN-04 broken manifest chain",
              [wrapper_pack] + chain_packs + [man_pack, _manifest_pack(pl2, vnb + 1)], "E-MAN-04")

        print(f"  manifest self-test: {passed} passed, {failed} failed")
        return failed == 0


# ===========================================================================
#  Trust-model vectors.
#
#  These exist to make the difference between "the observer verified this" and
#  "the observer stopped checking" visible. Implementing an anchored traversal
#  and then deleting the checks it was meant to enforce would be
#  indistinguishable from the outside without them, so each case below pairs an
#  outcome that MUST be clean with one that MUST NOT.
#
#  Every case runs against a trust file holding the Apex and nothing else, which
#  is the deployment RFC 9575 4.2 describes: the Observer caches a DIME identity
#  and the air interface supplies the rest.
# ===========================================================================
if HAVE_ED:

    def _apex_only_keyring():
        """A keyring holding the Apex and nothing else."""
        kr = observer.Keyring()
        kr.add(observer.APEX_DET, observer.APEX_HI,
               source=observer.SRC_TRUST_FILE, note="apex")
        return kr

    def _wrapper_pack(det_bytes, seed, vnb, vna):
        astm = [basic_id(det_bytes), system_msg(), _location_msg()]
        pages, _ = build_extended_wrapper_pages(astm, det_bytes, vnb, vna, seed)
        return pack([basic_id(det_bytes), _location_msg(), system_msg()] + pages)

    def _entity(seed_byte, raa, hda):
        """A standalone identity: (seed, public key, DET)."""
        seed = bytes([seed_byte]) * 32
        pub = ed25519.derive_pubkey(seed)
        return seed, pub, det.compute_det(pub, raa, hda, 5)

    def trust_self_test():
        print("\n--- DRIP trust-model self-test ---")
        passed = failed = 0
        vnb = 201699200
        vna = vnb + 86400

        def check(label, packs_list, expect_ids, now=None, expect_source=None,
                  expect_unlearned=()):
            """expect_ids is the EXACT set of error ids the run must produce.

            `expect_unlearned` names DETs whose key must NOT be in the keyring
            afterwards. Checking the error set alone is not enough: an observer
            that learned a key it should have refused can still report the right
            code and be wrong about the trust it now holds.
            """
            nonlocal passed, failed
            text = "\n".join(' '.join(f'{x:02X}' for x in p) for p in packs_list)
            keys = _apex_only_keyring()
            _f, _r, findings = observer.run(text, keys=keys, now=now)
            ids = {f.error_id for f in findings}
            ok = (ids == set(expect_ids))
            if ok and expect_source is not None:
                det_b, want = expect_source
                o = keys.origin(det_b)
                got = o.source if o else None
                ok = (got == want)
                if not ok:
                    print(f"         key provenance was {got!r}, expected {want!r}")
            for det_b in expect_unlearned:
                if keys.for_det(det_b) is not None:
                    print(f"         key for {observer._det_str(det_b)} was LEARNED "
                          f"and must not have been")
                    ok = False
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:44s} "
                  f"expect={','.join(sorted(expect_ids)) or '(clean)':22s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}")
            passed += ok
            failed += (not ok)

        c = build_chain(vnb, vna)
        chain_packs = [_be_pack(c['apex_raa']), _be_pack(c['raa_hda']),
                       _be_pack(c['hda_ua'])]
        wrap = _wrapper_pack(UA_DET, UA_PRIV_SEED, vnb, vna)

        # C1. An aircraft absent from the trust file, with the whole chain on
        # the air and a Wrapper. Nothing should be reported, and the key must be
        # recorded as having come from the air rather than from the file.
        check("C1 unknown aircraft, Apex-only trust file",
              chain_packs + [wrap], set(), expect_source=(UA_DET, observer.SRC_AIR))

        # C2. The same vectors with the Wrapper first. Arrival order must not
        # change the verdict (RFC 9575 6.4.2).
        check("C2 Wrapper ahead of the Link that endorses it",
              [wrap] + chain_packs, set(), expect_source=(UA_DET, observer.SRC_AIR))

        # C3. Two endorsements closed on each other, each correctly signed by
        # the other's key, with no path to the Apex. Every check the observer
        # had before the anchored traversal passes on this input.
        a_seed, a_pub, a_det = _entity(0x11, 255, 14340)
        b_seed, b_pub, b_det = _entity(0x22, 255, 14340)
        cyc = [_be_pack(_mk_be(vnb, vna, a_det, a_pub, b_det, b_seed), a_det),
               _be_pack(_mk_be(vnb, vna, b_det, b_pub, a_det, a_seed), b_det)]
        # E-KEY-01 is part of the expected outcome: neither identity may be
        # learned, so the Basic ID each pack carries stays unverifiable.
        check("C3 cyclic chain with no path to the Apex", cyc,
              {"E-LINK-03", "E-KEY-01"}, expect_unlearned=(a_det, b_det))

        # C4. An endorsement whose parent the observer does not hold, together
        # with a Wrapper signed by the key that endorsement carries. The
        # endorsement must not be allowed to bootstrap its own acceptance.
        orphan = _mk_be(vnb, vna, UA_DET, UA_PUB, c['hda_det'], _HDA_SEED)
        check("C4 unanchored Link offering a key",
              [_be_pack(orphan), wrap], {"E-LINK-03", "E-KEY-01"})

        # C5. A chain whose HDA-to-UA endorsement has expired at the reference
        # time. An expired endorsement teaches nothing, so the Wrapper that
        # depends on it stays unverified.
        expired = _mk_be(vnb, vnb + 60, UA_DET, UA_PUB, c['hda_det'], _HDA_SEED)
        now_unix = odid.EPOCH_2019 + vnb + 3600
        check("C5 endorsement outside its validity window",
              [_be_pack(c['apex_raa']), _be_pack(c['raa_hda']),
               _be_pack(expired), wrap],
              {"E-LINK-04", "E-KEY-01"}, now=now_unix)

        print(f"  trust self-test: {passed} passed, {failed} failed")
        return failed == 0


# ===========================================================================
#  Bluetooth Legacy vectors (session 3, 2026-09-29).
#
#  A REFERENCE ENCODER for ASTM F3411-22a §5.4.6 advertisements and RFC 9575
#  §5 FEC, written from the RFC text and independent of odid.py's decoder:
#  fec_scatter() below and odid.fec_check()/fec_recover() must agree for the
#  self-test to pass, which is the point.
#
#  Output is Format BT, exactly what DRIP_Sniffer.ino prints in `radio bt`:
#      #B addr=.. rssi=.. t_ms=.. len=29 t_us=.. atype=1
#      FA FF 0D <counter> <25-octet message>
#  The schedule is the transmitter's RFC 9575 §6.4 second (drone_fleet.cpp):
#      Basic ID, Location, System, Self ID, Operator ID, Manifest (FEC),
#      Basic ID, Location, System, one Link page (FEC)
# ===========================================================================
if HAVE_ED:
    BT_ADDR = "C2:44:52:49:50:00"
    _BT_T0 = 1_000_000                               # sniffer clock, microseconds

    def fec_scatter(auth_data, ts, auth_type=5, adl_override=None,
                    corrupt_parity=False, with_fec=True):
        """RFC 9575 §5.1, written from the text:
             stream = LPI | Length | TS(4) | Auth Data | ADL | null pad
             ADL = padding + 23, parity page = XOR of the data pages.
           with_fec=False gives the plain ASTM layout (for E-FEC-03)."""
        L = len(auth_data)
        if with_fec:
            used = 6 + L + 1
            data_pages = -(-used // 23)
            pages_n = data_pages + 1
        else:
            used = 6 + L
            data_pages = -(-used // 23)
            pages_n = data_pages
        stream = bytearray(data_pages * 23)
        stream[0] = pages_n - 1
        stream[1] = L
        stream[2:6] = struct.pack('<I', ts)
        stream[6:6 + L] = auth_data
        if with_fec:
            padding = data_pages * 23 - used
            stream[6 + L] = (padding + 23) if adl_override is None else adl_override
        pages = []
        for pg in range(data_pages):
            pages.append(_hdr(0x2) + bytes([(auth_type << 4) | pg])
                         + bytes(stream[pg * 23:(pg + 1) * 23]))
        if with_fec:
            par = bytearray(23)
            for pgb in pages:
                for k in range(23):
                    par[k] ^= pgb[2 + k]
            if corrupt_parity:
                par[0] ^= 0x01
            pages.append(_hdr(0x2) + bytes([(auth_type << 4) | data_pages]) + bytes(par))
        return pages

    def _mh(b):
        return det.cshake128(bytes(b), 8, N=b'', S=b"Remote ID Auth Hash")

    def _legacy_manifest_sam(prev8, link_hash8, msgs, vnb, vna, ua_det=UA_DET,
                             ua_seed=UA_PRIV_SEED):
        """SAM 0x03 over single 25-octet messages (RFC 9575 §4.4.3.1), Current
           hash over the whole Evidence as the firmware and E-MAN-05 do."""
        hashes = []
        for m in msgs:
            h = _mh(m)
            if h not in hashes:
                hashes.append(h)
        payload, curr = _manifest_payload(prev8, link_hash8, hashes, vnb, vna,
                                          ua_det=ua_det, ua_seed=ua_seed)
        return bytes([0x03]) + payload, curr

    def _bt_lines(recs):
        """recs = [(t_us, counter, msg25, addr)] -> Format BT text."""
        out = []
        for t, c, m, addr in recs:
            svc = bytes([0xFA, 0xFF, 0x0D, c & 0xFF]) + m
            out.append(f"#B addr={addr} rssi=-40 t_ms={t // 1000} len={len(svc)} "
                       f"t_us={t} atype=1")
            out.append(' '.join(f'{x:02X}' for x in svc))
        return "\n".join(out)

    def build_legacy_capture(seconds=3, erase=(), mutate=None, addr=BT_ADDR,
                             send_bid=True, second_man_prev=None):
        """A Format BT capture of `seconds` seconds of the §6.4 schedule, the
           whole Link chain paged with FEC and sent in full at the start (the
           bench sends one page per second; the assembler does not care).
           erase  = {(kind, second, page)} advertisements removed ("the air
                    lost them"), kind in {"man", "link"}
           mutate = callable(kind, second, pages) -> pages, to break a message
        """
        vnb = 201699200; vna = vnb + 86400
        c = build_chain(vnb, vna)
        link_hash = _mh(_be_full_sam(c['hda_ua']))
        recs = []
        t = _BT_T0
        ctr = {0: 0, 1: 0, 3: 0, 4: 0, 5: 0}
        auth_ctr = 0

        def put(m, cnt):
            nonlocal t
            recs.append((t, cnt, m, addr)); t += 30_000

        # the chain: three Links, FEC-paged
        for li, key in enumerate(("apex_raa", "raa_hda", "hda_ua")):
            pages = fec_scatter(_be_full_sam(c[key]), c[key]['vnb'])
            if mutate:
                pages = mutate("link", li, pages)
            for pg, pb in enumerate(pages):
                if ("link", li, pg) not in erase:
                    put(pb, auth_ctr)
            auth_ctr += 1

        prev = bytes(8)
        since_last = []
        for sec in range(seconds):
            sec_start = t
            loc = _hdr(0x1) + bytes([sec & 0xFF]) + bytes(23)     # distinct each second
            first = ([basic_id()] if send_bid else []) + [loc, system_msg(), self_id(), operator_id()]
            for m in first:
                put(m, ctr[m[0] >> 4]); ctr[m[0] >> 4] += 1
                since_last.append(m)
            use_prev = prev if (second_man_prev is None or sec != 1) else second_man_prev
            sam, curr = _legacy_manifest_sam(use_prev, link_hash, since_last, vnb + sec, vna)
            pages = fec_scatter(sam, vnb + sec)
            if mutate:
                pages = mutate("man", sec, pages)
            for pg, pb in enumerate(pages):
                if ("man", sec, pg) not in erase:
                    put(pb, auth_ctr)
            auth_ctr += 1
            prev = curr
            since_last = []
            loc2 = _hdr(0x1) + bytes([0x80 | (sec & 0x7F)]) + bytes(23)
            for m in ([basic_id()] if send_bid else []) + [loc2, system_msg()]:
                put(m, ctr[m[0] >> 4]); ctr[m[0] >> 4] += 1
                since_last.append(m)
            t = sec_start + 1_000_000                    # next second of the schedule
        return _bt_lines(recs)

    def _beacon_rows(pack_bytes, src_mac=bytes([0x02, 0x44, 0x52, 0x49, 0x50, 0x00]),
                     t_s=1.0):
        """One Format A frame (802.11 Beacon carrying the ODID vendor IE),
           received at sniffer time t_s seconds."""
        hdr = bytes([0x80, 0x00, 0, 0]) + b'\xff' * 6 + src_mac + src_mac + bytes(2)
        fixed = bytes(8) + bytes([0x64, 0x00, 0x21, 0x04])
        body = bytes([0xFA, 0x0B, 0xBC, 0x0D, 0x00]) + pack_bytes
        frame = hdr + fixed + bytes([0xDD, len(body)]) + body
        lines = [f"#F rssi=-40 ch=6 len={len(frame)}"]
        for off in range(0, len(frame), 16):
            hh, rem = divmod(t_s, 3600); mm, ss = divmod(rem, 60)
            pre = (f"{int(hh):02d}:{int(mm):02d}:{ss:09.6f} " if off == 0 else " " * 16)
            lines.append(pre + f"{off:06X}" + ''.join(f" {x:02X}" for x in frame[off:off + 16]))
        return "\n".join(lines)

    def legacy_self_test():
        print("\n--- Bluetooth Legacy / FEC self-test (session 3) ---")
        passed = failed = 0

        def check(label, text, expect_ids, health=None, pub=UA_PUB):
            """expect_ids: EXACT set of error ids. health: {key: value} that
               observer.capture_health['bt'] (or capture_health) must hold."""
            nonlocal passed, failed
            _f, _r, findings = observer.run(text, pub=pub)
            ids = {f.error_id for f in findings}
            ok = (ids == set(expect_ids))
            bad_h = []
            for k, v in (health or {}).items():
                got = observer.capture_health.get("bt", {}).get(k, observer.capture_health.get(k))
                if got != v:
                    bad_h.append(f"{k}={got} (want {v})")
            ok = ok and not bad_h
            print(f"  [{'PASS' if ok else 'FAIL'}] {label:46s} "
                  f"expect={','.join(sorted(expect_ids)) or '(clean)':10s} "
                  f"got: {', '.join(sorted(ids)) or 'no findings'}"
                  + (f"  HEALTH {'; '.join(bad_h)}" if bad_h else ""))
            passed += ok; failed += (not ok)

        clean = build_legacy_capture()
        check("L1 clean 3 s of the RFC 9575 6.4 schedule", clean, set(),
              {"auth_complete": 6, "auth_recovered": 0, "auth_lost": 0})

        check("L2 one Manifest page lost -> rebuilt by FEC",
              build_legacy_capture(erase={("man", 1, 3)}), set(),
              {"auth_recovered": 1, "auth_lost": 0})

        check("L3 one Link page lost -> rebuilt by FEC",
              build_legacy_capture(erase={("link", 2, 5)}), set(),
              {"auth_recovered": 1})

        check("L4 two Manifest pages lost -> counted, not judged",
              build_legacy_capture(erase={("man", 1, 2), ("man", 1, 4)}), set(),
              {"auth_lost": 1, "man_chain_gaps": 1})

        def bad_parity(kind, sec, pages):
            if kind == "man" and sec == 0:
                last = bytearray(pages[-1]); last[5] ^= 0x01; pages[-1] = bytes(last)
            return pages
        check("E-FEC-02 parity page corrupted",
              build_legacy_capture(mutate=bad_parity), {"E-FEC-02"})

        def bad_adl(kind, sec, pages):
            if kind == "man" and sec == 0:
                sam = pages[0]
                vnb = struct.unpack('<I', sam[4:8])[0]
                full = b"".join(p[2:] for p in pages[:-1])
                L = full[1]
                return fec_scatter(bytes(full[6:6 + L]), vnb, adl_override=7)
            return pages
        check("E-FEC-01 ADL value wrong", build_legacy_capture(mutate=bad_adl), {"E-FEC-01"})

        def no_fec(kind, sec, pages):
            if kind == "man" and sec == 0:
                full = b"".join(p[2:] for p in pages[:-1])
                L = full[1]
                vnb = struct.unpack('<I', pages[0][4:8])[0]
                return fec_scatter(bytes(full[6:6 + L]), vnb, with_fec=False)
            return pages
        check("E-FEC-03 Legacy Manifest without FEC",
              build_legacy_capture(mutate=no_fec), {"E-FEC-03"})

        # E-FEC-04: a FEC-paged Manifest inside a Wi-Fi Message Pack (Format B)
        vnb = 201699200
        sam, _ = _legacy_manifest_sam(bytes(8), bytes(8), [basic_id()], vnb, vnb + 60)
        fec_pages = fec_scatter(sam, vnb)
        pk = pack([basic_id()] + fec_pages[:8])
        if len(fec_pages) <= 8:
            check("E-FEC-04 FEC inside a Message Pack",
                  ' '.join(f'{x:02X}' for x in pk), {"E-FEC-04", "E-MAN-02", "E-MAN-03"},
                  pub=UA_PUB)
        else:
            print("  [SKIP] E-FEC-04 vector does not fit one pack")

        check("E-SEM-01 Legacy auth, no Basic ID from that address",
              build_legacy_capture(send_bid=False), {"E-SEM-01"})

        check("E-MAN-04 Legacy chain broken between consecutive Manifests",
              build_legacy_capture(second_man_prev=bytes([0xAA]) * 8), {"E-MAN-04"})

        # A Manifest hash whose message was lost: counted, not E-MAN-02
        lines = build_legacy_capture().split("\n")
        # drop second 0's first Location (type 0x1, first data octet 0x00): it
        # is the only message with those bytes, so exactly one Manifest hash
        # has nothing to match
        for i in range(1, len(lines), 2):
            tok = lines[i].split()
            if tok[4] == "12" and tok[5] == "00":
                del lines[i - 1:i + 1]
                break
        check("L5 Manifest covers a message not received",
              "\n".join(lines), set(), {"man_hash_unreceived": 1})

        # RFC 9575 §6.3 once-per-minute Link (session 3, 2026-10-04): the
        # BE:HDA,UA Link the Manifests reference never arrives (all 8 pages
        # lost), while the other Links do. A short capture cannot tell "late"
        # from "missing", so it is counted; one that runs on for more than
        # observer.LEGACY_LINK_WAIT_S after a Manifest reports E-MAN-03.
        no_leaf = {("link", 2, pg) for pg in range(8)}
        check("L8 Link not yet arrived, capture < 60 s -> counted",
              build_legacy_capture(erase=no_leaf), set(),
              {"man_link_unchecked": 3})
        check("E-MAN-03 Link missing for > 60 s (RFC 9575 6.3)",
              build_legacy_capture(seconds=65, erase=no_leaf), {"E-MAN-03"})

        # Mixed capture: a Wi-Fi Format A segment, then Bluetooth
        wp, _ = build_extended_wrapper_pages([basic_id(), system_msg(), _location_msg()],
                                             UA_DET, 201699200, 201699200 + 120, UA_PRIV_SEED)
        a_seg = _beacon_rows(pack([basic_id(), _location_msg(), system_msg()] + wp))
        mixed = "# DRIP-SNIFFER v1\n" + a_seg + "\n# radio=bt\n" + clean
        check("L6 mixed Wi-Fi + Bluetooth capture", mixed, set(), {"frames": 1})
        fmt, _r, _f = observer.run(mixed, pub=UA_PUB)
        ok = fmt.startswith("A+BT")
        print(f"  [{'PASS' if ok else 'FAIL'}] {'L7 mixed capture labelled A+BT':46s} got: {fmt}")
        passed += ok; failed += (not ok)

        # ---- Wi-Fi Manifest losses (session 3, 2026-10-04) ------------------
        # Format A carries receive times, so two Wi-Fi Manifests more than
        # observer.WIFI_MAN_GAP_US apart are not chain-compared: a Manifest
        # beacon was lost between them. Consecutive ones still are.
        vnb = 201699200; vna = vnb + 120
        wp, _ = build_extended_wrapper_pages([basic_id(), system_msg(), _location_msg()],
                                             UA_DET, vnb, vna, UA_PRIV_SEED)
        wpk = pack([basic_id(), _location_msg(), system_msg()] + wp)
        ph = _mh(wpk)
        cch = build_chain(vnb, vna)
        lh = _mh(_be_full_sam(cch['hda_ua']))
        chain_pk = [_be_pack(cch[k]) for k in ("apex_raa", "raa_hda", "hda_ua")]
        mans, prev = [], bytes(8)
        for k in range(3):                       # M0, M1, M2: one valid chain
            pl, curr = _manifest_payload(prev, lh, [ph], vnb + k, vna)
            mans.append(_manifest_pack(pl, vnb + k)); prev = curr
        pl_bad, _ = _manifest_payload(bytes([0xAA]) * 8, lh, [ph], vnb + 1, vna)
        man_bad = _manifest_pack(pl_bad, vnb + 1)

        def a_capture(timed_packs):
            return "# DRIP-SNIFFER v1\n" + "\n".join(_beacon_rows(p, t_s=t) for t, p in timed_packs)

        base = [(1.0 + i, p) for i, p in enumerate(chain_pk)] + [(5.0, wpk)]
        check("W1 Wi-Fi Manifest beacon lost -> gap, no E-MAN-04",
              a_capture(base + [(10.0, mans[0]), (16.0, mans[2])]), set(),
              {"man_chain_gaps": 1})
        check("E-MAN-04 Wi-Fi consecutive Manifests, chain broken",
              a_capture(base + [(10.0, mans[0]), (13.0, man_bad)]), {"E-MAN-04"})
        check("W2 Wi-Fi Manifests 3 s apart, chain intact",
              a_capture(base + [(10.0, mans[0]), (13.0, mans[1]), (16.0, mans[2])]), set())

        print(f"  legacy self-test: {passed} passed, {failed} failed")
        return failed == 0


if __name__ == "__main__":
    sys.exit(main())
