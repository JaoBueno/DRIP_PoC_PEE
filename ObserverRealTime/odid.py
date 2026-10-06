#!/usr/bin/env python3
# =============================================================================
#  DRIP Observer - odid.py
#  ASTM F3411-22a message decoding + DRIP framing + input parsers.
#
#  This is the pure decoding layer (no validation, no I/O). The observer
#  (observer.py) applies the error catalog (errors.py) to the structures
#  produced here.
#
#  STANDARDS
#    Message header / 25-byte message ... ASTM F3411-22a 5.4.5.4, Table 4
#    Message types ...................... ASTM F3411-22a Table 3
#    Basic ID ........................... ASTM F3411-22a Table 5
#    Authentication (pages 0 / 1-15) .... ASTM F3411-22a Tables 8, 9; 5.4.5.9-15
#    System ............................. ASTM F3411-22a Table 11
#    Self-ID / Operator ID .............. ASTM F3411-22a Tables 10, 12
#    Message Pack ....................... ASTM F3411-22a Table 13; 5.4.5.22
#    Wi-Fi Beacon vendor IE ............. ASTM F3411-22a 5.4.9, Table 20
#                                         (OUI FA-0B-BC, vendor type 0x0D)
#    DRIP SAM types (in Auth Type 5) .... RFC 9575 Table 1
#    DET prefix ......................... RFC 9374 Table 1 (2001:30::/28)
# =============================================================================

import re
import struct
import ipaddress

PROTO_VERSION = 0x2          # ASTM F3411-22a protocol version nibble
MSG_LEN = 25                 # every ODID message is exactly 25 bytes
EPOCH_2019 = 1546300800      # add to an ODID timestamp to get a Unix timestamp

MSG_TYPES = {0x0: "Basic ID", 0x1: "Location/Vector", 0x2: "Authentication",
             0x3: "Self-ID", 0x4: "System", 0x5: "Operator ID", 0xF: "Message Pack"}
AUTH_TYPES = {0: "None", 1: "UAS ID Signature", 2: "Operator ID Signature",
              3: "Message Set Signature", 4: "Network Remote ID",
              5: "Specific Authentication Method (SAM)"}
SAM_TYPES = {0x01: "DRIP Link", 0x02: "DRIP Wrapper",
             0x03: "DRIP Manifest", 0x04: "DRIP Frame"}     # RFC 9575 Table 1
ID_TYPES = {0: "None", 1: "Serial Number (CTA-2063-A)", 2: "CAA Registration ID",
            3: "UTM (UUID)", 4: "Specific Session ID"}
SSI_TYPES = {1: "IETF DRIP (DET)"}                          # ASTM Annex A5 / RFC 9153
DET_PREFIX = ipaddress.IPv6Network("2001:30::/28")          # RFC 9374 Table 1

# Wi-Fi Beacon vendor-specific IE markers (ASTM 5.4.9 / Table 20)
WLAN_VENDOR_ELEM = 0xDD
ODID_OUI = bytes([0xFA, 0x0B, 0xBC])
ODID_VTYPE = 0x0D
# Offset of the tagged-parameter section in an 802.11 Beacon:
#   24-byte MAC header + 12-byte fixed params (timestamp 8 + interval 2 + cap 2)
BEACON_TAGGED_START = 36


# ---------------------------------------------------------------------------
#  Input parsers
# ---------------------------------------------------------------------------
def looks_like_format_w(text):
    """True if the text looks like a Wireshark 'bytes only' export."""
    for line in text.splitlines():
        if re.match(r'^[0-9a-fA-F]{4}\s{2}[0-9a-fA-F]{2}\s', line):
            return True
    return False


def parse_format_w(text):
    """Wireshark 'Export Packet Dissections -> As Plain Text -> Bytes only'.
       Each packet is a block of 'OFFSET  HEXBYTES  ASCII' rows; a blank line
       separates packets. Returns a list of raw 802.11 frame byte strings."""
    frames = []
    cur = bytearray()
    for line in text.splitlines():
        # 4-hex-digit offset, two spaces, then the hex-byte region
        m = re.match(r'^([0-9a-fA-F]{4})\s{2}((?:[0-9a-fA-F]{2}\s+)+)', line)
        if m:
            row = bytes.fromhex(m.group(2).replace(' ', ''))[:16]  # cap 16 bytes/row
            cur += row
        elif line.strip() == '' and cur:
            frames.append(bytes(cur))
            cur = bytearray()
    if cur:
        frames.append(bytes(cur))
    return frames


def parse_format_b(text):
    """Flat hex, one record per line; '#' starts a comment; blank lines ignored.
       A comment containing 'expect: <ID>' tags the NEXT record (for test files).
       Returns a list of (bytes, expect_id_or_None)."""
    records = []
    pending = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith('#'):
            m = re.search(r'expect:\s*([A-Z0-9\-]+)', s)
            if m:
                pending = m.group(1)
            continue
        hexstr = re.sub(r'[^0-9a-fA-F]', '', s)
        if hexstr:
            records.append((bytes.fromhex(hexstr), pending))
            pending = None
    return records


# ---------------------------------------------------------------------------
#  Format A — over-the-air capture from DRIP_Sniffer (ESP32 #2)
#
#  One 802.11 frame per block, as a text2pcap-importable hexdump:
#
#      # DRIP-SNIFFER v1 ...                 <- banner (ignored)
#      #F rssi=-29 ch=6 len=271              <- metadata for the NEXT frame
#      00:08:03.553235 000000 80 00 00 00 FF FF ...   <- ts only on first row
#      000010 02 44 52 49 50 00 80 1C ...             <- continuation rows
#
#  A new frame starts whenever the offset returns to 0 — the same rule
#  text2pcap uses, so this parser and Wireshark always agree on framing.
#
#  WHY THIS FORMAT EXISTS
#    Format L (the transmitter's serial log) prints the pack the firmware
#    INTENDED to send, out of RAM, before esp_wifi_80211_tx() is called. It
#    cannot see whether the frame reached the air, whether the MAC header was
#    well formed, or which transmitter it came from. Format A is the air.
#
#  ROBUSTNESS: tolerates CRLF, '#' comments, and rows with or without leading
#  whitespace — arduino_logger.py .strip()s every line, so the sniffer's
#  alignment padding does not survive capture. Both forms are accepted.
# ---------------------------------------------------------------------------

# optional "HH:MM:SS.ffffff", 6-hex offset, then 2-hex bytes
_FMT_A_ROW = re.compile(
    r'^\s*(?:(\d{2}):(\d{2}):(\d{2})\.(\d{1,9})\s+)?'
    r'([0-9A-Fa-f]{6})((?:[ \t]+[0-9A-Fa-f]{2})+)\s*$')

_FMT_A_META = re.compile(
    r'^#F\s+rssi=(-?\d+)\s+ch=(\d+)\s+len=(\d+)')

_ALL_HEX = re.compile(r'^[0-9A-Fa-f]+$')


def looks_like_format_a(text):
    """True if this is a DRIP_Sniffer air capture.

    Anchored on a row at offset 000000 whose first byte is 0x80 (802.11
    Frame Control: management/beacon). That pairing is specific enough that
    Format B or W cannot trip it by accident.
    """
    if 'DRIP-SNIFFER' in text:
        return True
    for line in text.splitlines():
        m = _FMT_A_ROW.match(line)
        if m and int(m.group(5), 16) == 0:
            first = m.group(6).split()[0]
            if first.upper() == '80':
                return True
    return False


def parse_format_a(text, strict_len=True):
    """Parse a DRIP_Sniffer capture.

    Returns (frames, damaged) where
        frames  = [(meta, frame_bytes)]  -- frames that arrived INTACT
        damaged = [(meta, got_len)]      -- frames whose byte count did not
                                            match the sniffer's declared len

    meta may contain:
        rssi, ch, len   from the '#F' line preceding the frame
        t_us            microseconds since the SNIFFER booted (not wall clock)

    THE LENGTH CHECK (strict_len)
    -----------------------------
    The sniffer states how many bytes it is about to send: '#F ... len=271'.
    If the hexdump that follows does not total len, the frame did not survive
    the SERIAL LINK -- it was already damaged before the observer saw it.

    This matters because such a frame decodes as garbage, and garbage decodes
    as DRIP violations. MEASURED on a real 18,462-frame capture: 18 frames were
    damaged by a serial-side byte loss (0.1% of the data) and produced ALL 66
    findings in that run -- reported as "Wrong protocol version" and "Manifest
    chain broken", i.e. a USB glitch masquerading as a firmware fault.

    A frame that never arrived intact cannot testify about the drone that sent
    it. It is dropped here and counted, so the damage is reported as damage.

    Set strict_len=False to keep them (decoding them is almost never useful).
    """
    frames = []
    damaged = []
    cur = bytearray()
    cur_meta = {}
    pending = {}
    have = False

    def _close(meta, buf):
        """Accept a completed frame, or bin it if the byte count is wrong."""
        declared = meta.get("len")
        if strict_len and declared is not None and declared != len(buf):
            damaged.append((meta, len(buf)))
        else:
            frames.append((meta, bytes(buf)))

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue

        if s.startswith('#'):
            m = _FMT_A_META.match(s)
            if m:
                pending = {"rssi": int(m.group(1)),
                           "ch":   int(m.group(2)),
                           "len":  int(m.group(3))}
            continue

        m = _FMT_A_ROW.match(line)
        if not m:
            continue

        off = int(m.group(5), 16)
        row = bytes.fromhex(re.sub(r'\s+', '', m.group(6)))

        if off == 0:
            if have:
                _close(cur_meta, cur)
            cur = bytearray()
            cur_meta = dict(pending)
            pending = {}
            have = True
            if m.group(1) is not None:
                frac = (m.group(4) + "000000")[:6]      # normalise to microseconds
                cur_meta["t_us"] = ((int(m.group(1)) * 3600 +
                                     int(m.group(2)) * 60 +
                                     int(m.group(3))) * 1_000_000 + int(frac))
        if have:
            cur += row

    if have:
        _close(cur_meta, cur)
    return frames, damaged


def parse_mac_header(frame):
    """Decode the 802.11 MAC header (IEEE 802.11-2016 §9.2.4).

    The observer historically started at BEACON_TAGGED_START (36) and never
    looked at bytes 0..35 — so the transmitter address was invisible to it.
    That blindness is why a single-BSSID transmitter would have looked healthy
    to this tool while a real receiver saw one aircraft flickering between
    several identities.

    Returns None if the frame is too short. The MAC labels a finding and
    nothing more. No check binds it to a DET.
    """
    if len(frame) < 24:
        return None
    return {
        "fc":      frame[0],
        "subtype": (frame[0] >> 4) & 0x0F,
        "addr1":   bytes(frame[4:10]),    # DA  (broadcast for a beacon)
        "addr2":   bytes(frame[10:16]),   # SA  <- the transmitter
        "addr3":   bytes(frame[16:22]),   # BSSID
        "seq":     (int.from_bytes(frame[22:24], "little") >> 4) & 0x0FFF,
        "frag":    frame[22] & 0x0F,
    }


def mac_str(mac):
    """02:44:52:49:50:00"""
    return ":".join(f"{b:02X}" for b in mac)


def looks_like_format_b(text):
    """POSITIVE test for flat hex (Format B).

    Format B used to be the unconditional `else` of the dispatch: anything not
    recognised as L or W was DECLARED to be flat hex and decoded anyway. Fed an
    air capture, that produced 10157 confident findings from a flawless file —
    a wrong answer delivered with statistics, which is worse than an error.
    Format B is now something a file must LOOK like, not what it is by default.

    A Format B line is only hex (whitespace tolerated) and carries no offset
    prefix, so an offset-prefixed hexdump row can never satisfy it.
    """
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if _FMT_A_ROW.match(line):
            continue                                   # hexdump row -> not B
        h = re.sub(r'\s+', '', s)
        if len(h) >= 6 and len(h) % 2 == 0 and _ALL_HEX.match(h):
            return True
    return False


def diagnose_format(text):
    """Explain, in the user's terms, why no parser claimed this input."""
    lines = text.splitlines()
    a_rows = sum(1 for l in lines if _FMT_A_ROW.match(l))
    a_meta = sum(1 for l in lines if l.strip().startswith('#F '))
    hints = []
    if a_rows:
        hints.append(f"{a_rows} offset-prefixed hexdump row(s) "
                     f"(e.g. '000010 02 44 52 49 50 00 ...')")
    if a_meta:
        hints.append(f"{a_meta} '#F rssi=' marker(s)")
    msg = ["unrecognised input format - refusing to guess."]
    if hints:
        msg.append("  found: " + "; ".join(hints))
    if a_rows or a_meta:
        msg.append("  this looks like a DRIP_Sniffer air capture (Format A), but "
                   "looks_like_format_a() did not match it.")
        msg.append("  a Format A capture needs a row at offset 000000 starting "
                   "with 80 (802.11 beacon), or the '# DRIP-SNIFFER' banner.")
    else:
        msg.append("  expected one of: Format L (ESP32 serial log), "
                   "Format W (Wireshark bytes export),")
        msg.append("  Format A (DRIP_Sniffer air capture), or Format B (flat hex).")
    return "\n".join(msg)


def extract_drip_ie(frame, tagged_start=BEACON_TAGGED_START):
    """Walk the tagged parameters of an 802.11 Beacon and return the DRIP
       vendor IE as {counter, payload, ie_len}, or None if not present.
       payload = the Message Pack bytes (after OUI[3] + vtype[1] + counter[1])."""
    pos = tagged_start
    while pos + 1 < len(frame):
        tag_id = frame[pos]
        tag_len = frame[pos + 1]
        if pos + 2 + tag_len > len(frame):
            break
        body = frame[pos + 2: pos + 2 + tag_len]
        if (tag_id == WLAN_VENDOR_ELEM and len(body) >= 5
                and body[:3] == ODID_OUI and body[3] == ODID_VTYPE):
            return {"counter": body[4], "payload": body[5:], "ie_len": tag_len}
        pos += 2 + tag_len
    return None


# ---------------------------------------------------------------------------
#  Per-message decoders
# ---------------------------------------------------------------------------
def decode_header(b):
    """(message_type, protocol_version) from the 1-byte header."""
    return (b >> 4) & 0xF, b & 0xF


def _ts_unix(ts_2019):
    return ts_2019 + EPOCH_2019


def decode_basic_id(m):
    """ASTM Table 5. For ID Type 4 (Specific Session ID) + SSI Type 1 (IETF DRIP),
       the 16-byte DET is extracted."""
    id_type = m[1] >> 4
    ua_type = m[1] & 0xF
    uas_id = m[2:22]
    out = {"id_type": id_type, "id_type_name": ID_TYPES.get(id_type, "?"),
           "ua_type": ua_type, "uas_id_raw": uas_id, "det": None}
    if id_type == 4:
        ssi_type = uas_id[0]
        out["ssi_type"] = ssi_type
        out["ssi_type_name"] = SSI_TYPES.get(ssi_type, "?")
        if ssi_type == 1:                       # IETF DRIP -> next 16 bytes are the DET
            det = bytes(uas_id[1:17])
            out["det"] = det
            out["det_ipv6"] = str(ipaddress.IPv6Address(det))
    else:
        out["uas_id_text"] = uas_id.rstrip(b'\x00').decode('ascii', 'replace')
    return out


def decode_auth_page(m):
    """ASTM Tables 8 (page 0) and 9 (pages 1-15)."""
    auth_type = m[1] >> 4
    page_num = m[1] & 0xF
    out = {"auth_type": auth_type, "auth_type_name": AUTH_TYPES.get(auth_type, "?"),
           "page_num": page_num}
    if page_num == 0:
        out["last_page_reserved"] = (m[2] >> 4) & 0xF
        out["last_page_index"] = m[2] & 0xF
        out["length"] = m[3]
        ts = struct.unpack('<I', m[4:8])[0]
        out["timestamp_raw"] = ts
        out["timestamp_unix"] = _ts_unix(ts)
        out["auth_data"] = bytes(m[8:25])       # 17 bytes on page 0
    else:
        out["auth_data"] = bytes(m[2:25])       # 23 bytes on continuation pages
    return out


def decode_self_id(m):
    """ASTM Table 10."""
    return {"description_type": m[1],
            "description": m[2:25].rstrip(b'\x00').decode('ascii', 'replace')}


def decode_operator_id(m):
    """ASTM Table 12."""
    return {"operator_id_type": m[1],
            "operator_id": m[2:22].rstrip(b'\x00').decode('ascii', 'replace')}


def decode_system(m):
    """ASTM F3411-22a Table 11 (multi-byte numeric fields are little-endian).
    Offset 20/len 4 = Timestamp (32-bit DRIP-epoch Unix seconds, "time of
    applicability"); offset 24/len 1 = genuinely Reserved (not decoded).
    NOTE: firmware builds prior to the F3411System struct fix left this field
    zero-filled (it was folded into a 5-byte `reserved` array); timestamp_unix
    will read as a constant, meaningless value against those older captures."""
    return {"flags": m[1],
            "operator_lat": struct.unpack('<i', m[2:6])[0] / 1e7,
            "operator_lon": struct.unpack('<i', m[6:10])[0] / 1e7,
            "area_count": struct.unpack('<H', m[10:12])[0],
            "area_radius_m": m[12] * 10,
            "area_ceiling_enc": struct.unpack('<H', m[13:15])[0],
            "area_floor_enc": struct.unpack('<H', m[15:17])[0],
            "ua_classification": m[17],
            "operator_alt_enc": struct.unpack('<H', m[18:20])[0],
            "timestamp_raw": struct.unpack('<I', m[20:24])[0],
            "timestamp_unix": _ts_unix(struct.unpack('<I', m[20:24])[0])}


def decode_location(m):
    """ASTM F3411-22a Table 6 (Location/Vector Message) + Table 7 (encodings).
    Byte layout confirmed against the firmware's F3411Location struct
    (f3411_messages.h/.cpp) — status_flags | direction | speed | speed_vert |
    lat(4,LE) | lon(4,LE) | alt_pressure(2,LE) | alt_geodetic(2,LE) |
    height(2,LE) | acc | acc | timestamp(2,LE) | ts_acc | reserved."""
    status_flags = m[1]
    op_status    = (status_flags >> 4) & 0xF
    height_type  = (status_flags >> 2) & 0x1
    dir_segment  = (status_flags >> 1) & 0x1
    speed_mult   = status_flags & 0x1

    dir_stored = m[2]
    direction = dir_stored + 180 if dir_segment else dir_stored   # Table 7

    speed_byte = m[3]
    speed_mps = speed_byte * 0.75 + 63.75 if speed_mult else speed_byte * 0.25  # Table 7

    speed_vert_raw = struct.unpack('<b', m[4:5])[0]
    vspeed_mps = speed_vert_raw * 0.5

    lat = struct.unpack('<i', m[5:9])[0] / 1e7
    lon = struct.unpack('<i', m[9:13])[0] / 1e7

    def dec_alt(raw):      # Table 7: (enc * 0.5) - 1000; 0xFFFF/0 = unknown
        if raw in (0xFFFF, 0x0000):
            return None
        return raw * 0.5 - 1000.0

    alt_pressure = dec_alt(struct.unpack('<H', m[13:15])[0])
    alt_geodetic = dec_alt(struct.unpack('<H', m[15:17])[0])
    height       = dec_alt(struct.unpack('<H', m[17:19])[0])

    hv_acc = m[19]
    vert_acc, horiz_acc = (hv_acc >> 4) & 0xF, hv_acc & 0xF
    bs_acc = m[20]
    baro_acc, speed_acc = (bs_acc >> 4) & 0xF, bs_acc & 0xF

    ts_raw = struct.unpack('<H', m[21:23])[0]
    ts_seconds_in_hour = ts_raw / 10.0     # tenths of a second since the last UTC hour

    return {
        "op_status": op_status, "height_type": height_type,
        "direction_deg": direction, "speed_mps": speed_mps, "vspeed_mps": vspeed_mps,
        "lat": lat, "lon": lon,
        "alt_pressure_m": alt_pressure, "alt_geodetic_m": alt_geodetic, "height_m": height,
        "vert_accuracy": vert_acc, "horiz_accuracy": horiz_acc,
        "baro_accuracy": baro_acc, "speed_accuracy": speed_acc,
        "location_ts_s_in_hour": ts_seconds_in_hour,
    }


_DECODERS = {0x0: decode_basic_id, 0x1: decode_location, 0x2: decode_auth_page,
             0x3: decode_self_id, 0x4: decode_system, 0x5: decode_operator_id}


def decode_message(m):
    """Decode a single 25-byte ODID message into a dict."""
    m = bytes(m)
    if len(m) != MSG_LEN:
        return {"_error": "bad_length", "length": len(m), "raw": m}
    mtype, ver = decode_header(m[0])
    d = {"type": mtype, "type_name": MSG_TYPES.get(mtype, "Unknown"),
         "version": ver}
    dec = _DECODERS.get(mtype)
    if dec:
        d.update(dec(m))
    d["raw"] = m           # set last: the full 25-byte message always wins
    return d


# ---------------------------------------------------------------------------
#  Message Pack + multi-page Authentication reassembly
# ---------------------------------------------------------------------------
def split_pack(pack):
    """ASTM Table 13. Returns header info + the list of raw 25-byte messages
       the pack claims to contain (sliced by count)."""
    pack = bytes(pack)
    mtype, ver = decode_header(pack[0])
    out = {"type": mtype, "version": ver, "raw": pack}
    if len(pack) < 3:
        out["_error"] = "pack_too_short"
        out["messages_raw"] = []
        out["bytes_available"] = max(0, len(pack) - 3)
        return out
    out["msg_size"] = pack[1]
    out["count"] = pack[2]
    out["bytes_available"] = len(pack) - 3
    msgs = []
    pos = 3
    for _ in range(pack[2]):
        msgs.append(pack[pos:pos + MSG_LEN])
        pos += MSG_LEN
    out["messages_raw"] = msgs
    return out


def reassemble_auth(decoded_msgs):
    """Group consecutive Authentication messages (a page-0 followed by its
       continuation pages) into complete auth payloads. Returns a list of dicts.
       This is the step the example serial log failed at ('could not reassemble')."""
    results = []
    n = len(decoded_msgs)
    i = 0
    while i < n:
        d = decoded_msgs[i]
        if d.get("type") == 0x2 and d.get("page_num") == 0:
            last = d.get("last_page_index", 0)
            data = bytearray(d.get("auth_data", b''))     # page 0: 17 bytes
            pages = [0]
            expected = 1
            j = i + 1
            while (j < n and decoded_msgs[j].get("type") == 0x2
                   and decoded_msgs[j].get("page_num") == expected
                   and expected <= last):
                data += decoded_msgs[j].get("auth_data", b'')   # 23 bytes each
                pages.append(expected)
                expected += 1
                j += 1
            length = d.get("length", 0)
            payload = bytes(data[:length])
            complete = (pages == list(range(last + 1))) and (len(data) >= length)
            sam_type = payload[0] if payload else None
            results.append({
                "auth_type": d.get("auth_type"),
                "last_page_index": last,
                "length": length,
                "timestamp_unix": d.get("timestamp_unix"),
                "pages_present": pages,
                "complete": complete,
                "sam_type": sam_type,
                "sam_name": SAM_TYPES.get(sam_type) if sam_type is not None else None,
                "sam_data": payload[1:] if payload else b'',
                "start_index": i,
            })
            i = j
        else:
            i += 1
    return results


# ---------------------------------------------------------------------------
#  Format L parser  (ESP32 serial log, Format L = Log)
#  Each TX cycle contains a [VSIE] block and a [Pack] block.
#  We extract from the [Pack] block because it is the clean Message Pack
#  without the 802.11 IE wrapper overhead — identical to what we validate.
#
#  Line pattern inside the Pack block:
#    0x00: DD E9 FA 0B BC 0D 00 F2 19 ...
#  Prefix is the hex offset (0x00, 0x10 ...) followed by a colon and bytes.
# ---------------------------------------------------------------------------
import re as _re

def looks_like_format_l(text):
    """True if this looks like an ESP32 serial dump with [Pack] blocks."""
    return bool(_re.search(r'^\[Pack\]', text, _re.MULTILINE))


def parse_format_l(text):
    """Parse Format L (ESP32 serial log). Yields dicts:
         {tx_cnt, counter, cycle, pack_bytes}
       pack_bytes = the full Message Pack (starting with the F2 19 NN header).
    """
    results = []
    lines = text.splitlines()
    n = len(lines)
    i = 0
    # State carried across adjacent lines
    cur_cnt = None
    cur_counter = None
    cur_cycle = None
    while i < n:
        s = lines[i].strip()

        # TX cycle header: "TX cnt=0x00 (  0) | Cycle A — Wrapper"
        m = _re.match(r'TX cnt=0x([0-9A-Fa-f]+)\s*\(\s*(\d+)\s*\)\s*\|\s*Cycle\s+\S+\s*[—-]\s*(.+)', s)
        if m:
            cur_cnt = int(m.group(1), 16)
            cur_cycle = m.group(3).strip()
            i += 1
            continue

        # OUI line carries the counter byte
        m = _re.match(r'OUI=FA-0B-BC\s+vendor_type=0x0D\s+counter=0x([0-9A-Fa-f]+)', s)
        if m:
            cur_counter = int(m.group(1), 16)
            i += 1
            continue

        # [Pack] header + hdr= line: collect the hex-dump lines that follow
        if s.startswith('[Pack]'):
            # Next line should be "hdr=[F2 19 09]  msg_size=25  count=9"
            i += 1
            if i >= n:
                break
            hdr_line = lines[i].strip()
            if not hdr_line.startswith('hdr=['):
                continue
            i += 1
            # Collect 0xNN: hex rows until a non-hex line
            raw = bytearray()
            while i < n:
                row = lines[i].strip()
                m2 = _re.match(r'^0x[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)', row)
                if m2:
                    raw += bytes.fromhex(m2.group(1).replace(' ', ''))
                    i += 1
                else:
                    break
            if raw:
                results.append({
                    "tx_cnt": cur_cnt,
                    "counter": cur_counter,
                    "cycle": cur_cycle,
                    "pack_bytes": bytes(raw),
                })
            continue
        i += 1
    return results


# ---------------------------------------------------------------------------
#  Extended Transport Wrapper — Evidence reconstruction  (RFC 9575 §4.3.2)
#
#  To verify a Wrapper's signature, the receiver rebuilds the bytes the UA
#  signed. Per §4.3.2 the Evidence = "all the messages in the Message Pack
#  (excluding the Authentication Message ...) in ASTM Message Type order".
#
#  RFC-MANDATED  : same pack, exclude Auth (type 0x2), ascending Message Type.
#  OUR CONVENTION: the RFC does not define the order among messages of the SAME
#                  type (e.g. two Basic IDs). We use a STABLE sort — ties keep
#                  their original Message Pack order. The transmitter
#                  (drip_auth.cpp collect_evidence_order) uses the identical
#                  rule, so signatures over duplicate-type packs still verify.
#                  For the current PoC packs (all distinct types) no tie occurs.
# ---------------------------------------------------------------------------
def reconstruct_wrapper_evidence(decoded_msgs):
    """Return the Evidence bytes (concatenated 25-byte ASTM messages) that a
       DRIP Wrapper over Extended Transport signs over, given the pack's decoded
       messages. Excludes Authentication messages; stable ascending type sort."""
    non_auth = [d for d in decoded_msgs if d.get("type") != 0x2]
    # stable sort by message type (Python's sort is stable -> ties keep order)
    ordered = sorted(non_auth, key=lambda d: d.get("type", 0xFF))
    return b"".join(bytes(d["raw"]) for d in ordered)


# ---------------------------------------------------------------------------
#  DRIP Link (Broadcast Endorsement) SAM decoding  (RFC 9575 §4.2 / Figure 5)
#
#  sam_data = the auth payload AFTER the 1-byte SAM Type (which is 0x01 for Link).
#  Layout (136 bytes): VNB(4) | VNA(4) | DET_child(16) | HI_child(32) |
#                      DET_parent(16) | Signature(64)
#  The parent signed the first 72 bytes (VNB..DET_parent); the SAM Type octet
#  is NOT part of the signed region (§4.1 convention).
# ---------------------------------------------------------------------------
def decode_link_sam(sam_data):
    """Decode DRIP Link SAM data. Returns a BE dict or None if too short."""
    if len(sam_data) < 136:
        return None
    return {
        "vnb": int.from_bytes(sam_data[0:4], "little"),
        "vna": int.from_bytes(sam_data[4:8], "little"),
        "det_child":  bytes(sam_data[8:24]),
        "hi_child":   bytes(sam_data[24:56]),
        "det_parent": bytes(sam_data[56:72]),
        "sig":        bytes(sam_data[72:136]),
        "signed_region": bytes(sam_data[0:72]),   # VNB|VNA|DET_child|HI_child|DET_parent
    }


# ---------------------------------------------------------------------------
#  DRIP Manifest SAM decoding  (RFC 9575 §4.4 / Figure 8)
#
#  sam_data = the auth payload AFTER the 1-byte SAM Type (0x03).
#  Layout: VNB(4) | VNA(4) | Evidence | UA_DET(16) | Signature(64)
#  Evidence = Prev(8) | Curr(8) | LinkHash(8) | ASTM Message Hashes(N*8)
#  §4.4.1 sanity: Evidence length MUST be a multiple of 8; hashCount = len/8 - 3.
# ---------------------------------------------------------------------------
def decode_manifest_sam(sam_data):
    """Decode DRIP Manifest SAM data. Returns a dict or None if malformed."""
    ev_len = len(sam_data) - 8 - 16 - 64      # minus VNB+VNA, DET, Sig
    if ev_len < 24 or ev_len % 8 != 0:        # need >=3 ledger hashes, multiple of 8
        return None
    ev = sam_data[8:8 + ev_len]
    n_astm = (ev_len - 24) // 8
    return {
        "vnb": int.from_bytes(sam_data[0:4], "little"),
        "vna": int.from_bytes(sam_data[4:8], "little"),
        "evidence":    bytes(ev),
        "prev":        bytes(ev[0:8]),
        "curr":        bytes(ev[8:16]),
        "link_hash":   bytes(ev[16:24]),
        "astm_hashes": [bytes(ev[24 + i * 8:32 + i * 8]) for i in range(n_astm)],
        "det":         bytes(sam_data[8 + ev_len:8 + ev_len + 16]),
        "sig":         bytes(sam_data[8 + ev_len + 16:8 + ev_len + 80]),
        "signed_region": bytes(sam_data[0:8 + ev_len + 16]),   # VNB|VNA|Evidence|DET
        "hash_count":  n_astm,
    }


# =============================================================================
#  FORMAT BT + LEGACY TRANSPORT  (session 3, 2026-09-29)
#
#  Bluetooth Legacy advertising, ASTM F3411-22a §5.4.6, as captured by
#  DRIP_Sniffer.ino in `radio bt` mode. Parsing and reassembly only: no
#  judgement here, exactly like the rest of this module. observer.py applies
#  the error catalog.
#
#  FORMAT BT - one advertisement = one metadata line + one hex line:
#      #B addr=C2:44:52:49:50:00 rssi=-42 t_ms=12345 len=29 t_us=12345678 atype=1
#      FA FF 0D 07 02 12 ...
#  The hex is the Service Data AD field from the UUID on (ASTM Table 14):
#      [FA FF] UUID 0xFFFA LE | [0D] App Code | [counter] | [25-octet message]
#  The first four fields are the MOCK_DET_DRIP fork's Format BT; t_us and atype
#  were appended by this project's sniffer after len.
#
#  WHY LEGACY NEEDS ITS OWN REASSEMBLY
#  On Wi-Fi every Authentication message arrives whole, inside one Message
#  Pack, and reassemble_auth() pairs pages that sit next to each other. On
#  Legacy each page is a separate advertisement, possibly several seconds apart
#  (the Link: one page per second, RFC 9575 §6.4), repeated, and interleaved
#  with other messages. Pages of one Authentication message are correlated by
#  the sender address and the Message Counter, which is identical on every page
#  of one message (ASTM F3411-22a §5.4.4.2, BUR0060; RFC 9575 §5.2).
#
#  DRIP SINGLE PAGE FEC - RFC 9575 §5
#  Mandatory on Legacy (§6.1), forbidden in Message Packs (§6.2). Layout, over
#  the continuous stream of 23-octet page payloads:
#      Auth Headers(6) | Auth Data(Length) | ADL(1) | null pad | parity(23)
#  ADL = padding + 23. Last Page Index includes the parity page. Length counts
#  Auth Data only. The parity page is the XOR of every data page's payload, so
#  any ONE missing page, except page 0, is the XOR of all the others.
#
#  RFC 9575 FIGURE 12 - POSITION TAKEN (open question in PROGRESS.md)
#  The pseudocode's page-index arithmetic disagrees with the §5.2 prose; for
#  Length 145 it yields a negative octet index. This decoder follows the prose,
#  which is also what the transmitter (drip_auth_scatter_fec) implements: the
#  ADL octet is the first octet after the last Auth Data octet, in the stream.
# =============================================================================

_FMT_BT_META = re.compile(
    r'^#B\s+addr=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+rssi=(-?\d+)\s+'
    r't_ms=(\d+)\s+len=(\d+)(?:\s+t_us=(\d+))?(?:\s+atype=(\d+))?')

BT_UUID = bytes([0xFA, 0xFF])        # 0xFFFA little-endian (ASTM Table 14)
BT_APP_CODE = 0x0D                   # Open Drone ID
BT_SVC_HDR = 4                       # UUID(2) + App Code(1) + counter(1)
AUTH_HDR_OCTETS = 6                  # LPI(1) + Length(1) + Timestamp(4), RFC 9575 Fig 2
PAGE_PAYLOAD = 23                    # payload octets per Authentication page
FEC_MAX_PAGES = 16                   # RFC 9575 §3.2.1: pages 0..15


def looks_like_format_bt(text):
    """True if the capture holds at least one Format BT record."""
    for line in text.splitlines():
        if _FMT_BT_META.match(line.strip()):
            return True
    return False


def parse_bt_record(meta_match, hex_line):
    """Decode one Format BT record. Returns (record, None) for an ODID advert,
       (None, got_len) when the hex line does not total the declared len
       (capture-pipeline damage, like Format A's W-CAP-01), or (None, None) for
       Service Data that is not UUID 0xFFFA / App Code 0x0D."""
    m = meta_match
    declared = int(m.group(4))
    try:
        svc = bytes.fromhex(re.sub(r'[^0-9A-Fa-f]', '', hex_line))
    except ValueError:
        return None, -1
    if len(svc) != declared:
        return None, len(svc)
    if len(svc) < BT_SVC_HDR + MSG_LEN or svc[0:2] != BT_UUID or svc[2] != BT_APP_CODE:
        return None, None
    t_us = int(m.group(5)) if m.group(5) is not None else int(m.group(3)) * 1000
    return {
        "addr":    m.group(1).upper(),
        "rssi":    int(m.group(2)),
        "t_us":    t_us,
        "atype":   int(m.group(6)) if m.group(6) is not None else None,
        "counter": svc[3],
        "msg":     bytes(svc[BT_SVC_HDR:BT_SVC_HDR + MSG_LEN]),
        "len":     declared,
    }, None


def parse_format_bt(text):
    """Parse every Format BT record in `text`.
       Returns (records, damaged): records in file order; damaged = [(meta, got)]
       for records whose hex did not total the declared len."""
    records, damaged = [], []
    meta = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        m = _FMT_BT_META.match(s)
        if m:
            meta = m
            continue
        if meta is None or s.startswith('#'):
            continue
        rec, got = parse_bt_record(meta, s)
        if rec is not None:
            records.append(rec)
        elif got is not None:
            damaged.append(({"addr": meta.group(1).upper(), "len": int(meta.group(4))}, got))
        meta = None
    return records, damaged


def split_capture_segments(text):
    """Split a capture that may mix Wi-Fi (Format A) and Bluetooth (Format BT)
       records into contiguous segments, in FILE ORDER:
           [("A", text_chunk), ("BT", text_chunk), ...]
       The sniffer switches radios at runtime (`radio wifi|bt`), so one file can
       hold both. Order matters: a UA's Manifest chain continues across a
       switch (the transmitter keeps one ledger per drone)."""
    segs = []
    kind, buf = None, []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if _FMT_BT_META.match(line.strip()):
            if kind != "BT":
                if buf:
                    segs.append((kind or "A", "\n".join(buf)))
                kind, buf = "BT", []
            buf.append(line)
            if i + 1 < len(lines):
                buf.append(lines[i + 1])        # the hex line belongs to the record
            i += 2
            continue
        if kind == "BT" and (_FMT_A_ROW.match(line) or _FMT_A_META.match(line.strip())):
            segs.append(("BT", "\n".join(buf)))
            kind, buf = "A", []
        if kind is None:
            kind = "A"
        buf.append(line)
        i += 1
    if buf:
        segs.append((kind or "A", "\n".join(buf)))
    return segs


# ---------------------------------------------------------------------------
#  DRIP Single Page FEC (RFC 9575 §5)
# ---------------------------------------------------------------------------
def _ceil_div(a, b):
    return -(-a // b)


def fec_expected_pages(length):
    """(pages_without_fec, pages_with_fec) for an Authentication message whose
       Length field is `length` (RFC 9575 §5.1, Appendix B.1)."""
    no_fec = _ceil_div(AUTH_HDR_OCTETS + length, PAGE_PAYLOAD)
    with_fec = _ceil_div(AUTH_HDR_OCTETS + length + 1, PAGE_PAYLOAD) + 1
    return no_fec, with_fec


def fec_check(pages):
    """Inspect a COMPLETE, ordered list of 25-octet Authentication pages.

    Returns a dict:
        fec          True if the page count is the FEC layout, False if it is
                     the plain layout, None if it is neither
        adl_ok       ADL value and null padding as §5.1 requires (None if no FEC)
        parity_ok    parity page == XOR of the data pages (None if no FEC)
        detail       text for a finding
    Pure inspection; the caller decides what is a finding."""
    p0 = pages[0]
    lpi, length = p0[2] & 0x0F, p0[3]
    no_fec, with_fec = fec_expected_pages(length)
    n = lpi + 1
    out = {"fec": None, "adl_ok": None, "parity_ok": None, "detail": ""}
    if n == no_fec:
        out["fec"] = False
        return out
    if n != with_fec:
        out["detail"] = (f"LPI={lpi} fits neither the plain ({no_fec} pages) nor the "
                         f"FEC ({with_fec} pages) layout for Length={length}")
        return out
    out["fec"] = True
    stream = b"".join(p[2:25] for p in pages[:-1])
    adl_pos = AUTH_HDR_OCTETS + length
    padding = len(stream) - adl_pos - 1
    adl = stream[adl_pos]
    pad_ok = all(b == 0 for b in stream[adl_pos + 1:])
    out["adl_ok"] = (adl == padding + PAGE_PAYLOAD) and pad_ok
    if not out["adl_ok"]:
        out["detail"] = (f"ADL={adl} expected {padding + PAGE_PAYLOAD}"
                         + ("" if pad_ok else ", padding not null"))
    parity = bytearray(PAGE_PAYLOAD)
    for p in pages[:-1]:
        for k in range(PAGE_PAYLOAD):
            parity[k] ^= p[2 + k]
    out["parity_ok"] = bytes(parity) == bytes(pages[-1][2:25])
    if not out["parity_ok"]:
        out["detail"] = (out["detail"] + "; " if out["detail"] else "") + "parity page mismatch"
    return out


def fec_recover(pages_by_num, lpi):
    """Rebuild the ONE missing page of a FEC-protected message (RFC 9575 §5.2:
       XOR of every other page's payload, parity page included). Page 0 carries
       the Last Page Index, so it must be present for `lpi` to be known.
       Returns (page_number, page_bytes) or None."""
    missing = [p for p in range(lpi + 1) if p not in pages_by_num]
    if len(missing) != 1 or missing[0] == 0:
        return None
    miss = missing[0]
    acc = bytearray(PAGE_PAYLOAD)
    for p, b in pages_by_num.items():
        if p <= lpi:
            for k in range(PAGE_PAYLOAD):
                acc[k] ^= b[2 + k]
    p0 = pages_by_num[0]
    header = bytes([p0[0], (p0[1] & 0xF0) | miss])     # same type/version and Auth Type
    return miss, header + bytes(acc)


# ---------------------------------------------------------------------------
#  Legacy reassembly
# ---------------------------------------------------------------------------
class LegacyAssembler:
    """Turn a stream of Format BT records into messages and Authentication
    messages, per sender address.

    feed(rec) returns a list of events, in the order they become final:
        ("msg",  rec)          a non-Authentication ASTM message
        ("auth", group)        an Authentication message, complete or not
    flush() closes every open Authentication message (end of capture).

    group = {
        "addr", "counter", "t_first_us", "t_last_us",
        "pages":      [25-octet pages in page order] if usable, else None,
        "pages_by_num": {page: bytes} as received,
        "status":     "complete" | "recovered" | "lost" | "no_page0",
        "recovered_page": page number rebuilt by FEC, or None,
        "missing":    [page numbers missing],
        "lpi", "length", "sam_type"   (None when page 0 never arrived)
    }

    Copies: the controller repeats an advertisement until its data changes, so
    most messages arrive 1-3 times. A repeat of an ordinary message (same
    address, counter and bytes, within DUP_WINDOW_US) is dropped here, so the
    observer judges each transmitted message once. A page already held for an
    open Authentication message is likewise ignored.

    Closing: an Authentication message is emitted as soon as all its pages are
    present, or when AUTH_TIMEOUT_US passes with no new page (a Link's pages are
    one second apart), or at flush(). The counter then becomes free again: it
    wraps after 256 Authentication messages, minutes later."""

    DUP_WINDOW_US = 2_000_000
    AUTH_TIMEOUT_US = 20_000_000

    def __init__(self):
        self._open = {}          # (addr, counter) -> group under construction
        self._last_msg = {}      # (addr, type) -> (counter, bytes, t_us)
        self._done = {}          # (addr, counter) -> t_us when closed (repeat guard)

    def _new_group(self, rec):
        return {"addr": rec["addr"], "counter": rec["counter"],
                "t_first_us": rec["t_us"], "t_last_us": rec["t_us"],
                "pages": None, "pages_by_num": {}, "status": None,
                "recovered_page": None, "missing": [], "lpi": None,
                "length": None, "sam_type": None}

    def _finish(self, key, g):
        pb = g["pages_by_num"]
        p0 = pb.get(0)
        if p0 is None:
            g["status"] = "no_page0"
            g["missing"] = [0]
        else:
            lpi = p0[2] & 0x0F
            g["lpi"], g["length"] = lpi, p0[3]
            g["sam_type"] = p0[8]
            missing = [p for p in range(lpi + 1) if p not in pb]
            g["missing"] = missing
            if not missing:
                g["status"] = "complete"
                g["pages"] = [pb[p] for p in range(lpi + 1)]
            else:
                rec = fec_recover(pb, lpi)
                # Recovery only makes sense when the layout IS the FEC layout.
                _no, with_fec = fec_expected_pages(g["length"])
                if rec is not None and lpi + 1 == with_fec:
                    num, page = rec
                    full = dict(pb)
                    full[num] = page
                    g["pages"] = [full[p] for p in range(lpi + 1)]
                    g["status"] = "recovered"
                    g["recovered_page"] = num
                else:
                    g["status"] = "lost"
        self._done[key] = g["t_last_us"]
        return ("auth", g)

    def feed(self, rec):
        events = []
        t = rec["t_us"]
        # Time-out Authentication messages that stopped receiving pages.
        for key in [k for k, g in self._open.items()
                    if t - g["t_last_us"] > self.AUTH_TIMEOUT_US]:
            events.append(self._finish(key, self._open.pop(key)))

        msg = rec["msg"]
        mtype = msg[0] >> 4
        addr = rec["addr"]
        if mtype != 0x2:
            last = self._last_msg.get((addr, mtype))
            if (last is not None and last[0] == rec["counter"] and last[1] == msg
                    and t - last[2] <= self.DUP_WINDOW_US):
                self._last_msg[(addr, mtype)] = (last[0], last[1], t)
                return events                       # a repeat of the same advertisement
            self._last_msg[(addr, mtype)] = (rec["counter"], msg, t)
            events.append(("msg", rec))
            return events

        key = (addr, rec["counter"])
        g = self._open.get(key)
        if g is None:
            done_t = self._done.get(key)
            if done_t is not None and t - done_t <= self.AUTH_TIMEOUT_US:
                return events                       # a late repeat of a closed message
            g = self._new_group(rec)
            self._open[key] = g
        page = msg[1] & 0x0F
        if page not in g["pages_by_num"]:
            g["pages_by_num"][page] = msg
        g["t_last_us"] = t
        p0 = g["pages_by_num"].get(0)
        if p0 is not None:
            lpi = p0[2] & 0x0F
            n_have = sum(1 for p in range(lpi + 1) if p in g["pages_by_num"])
            _no, with_fec = fec_expected_pages(p0[3])
            # Close as soon as the message is usable: every page present, or
            # every page but one of a FEC layout once the LAST page (the parity)
            # is in, so the missing page can only be a lost one. Closing early
            # keeps Manifests in time order for the chain check.
            if (n_have == lpi + 1 or
                    (n_have == lpi and lpi + 1 == with_fec and lpi in g["pages_by_num"]
                     and page == lpi)):
                events.append(self._finish(key, self._open.pop(key)))
        return events

    def flush(self):
        events = [self._finish(k, g) for k, g in sorted(self._open.items(),
                                                          key=lambda kv: kv[1]["t_first_us"])]
        self._open.clear()
        return events
