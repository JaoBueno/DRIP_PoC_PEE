#pragma once
#include <stdint.h>
#include "f3411_messages.h"

// ---------------------------------------------------------------------------
// Shared ASTM F3411-22a Authentication Message page framing
//
// This is the SINGLE source of truth for how SAM Authentication Data is split
// into 25-byte ASTM Auth Message pages. The Link, Wrapper and Manifest builders
// all call drip_auth_scatter() so the wire framing is identical and correct.
//
// Correct page layout (ASTM F3411-22a Table 8 + RFC 9575 §3.2 / §3.2.1):
//
//   Page 0  (one 25-byte ASTM Auth Message, MessageType 0x2):
//     [0]      0x22                       MessageType(0x2)<<4 | ProtoVer(0x2)
//     [1]      0x50                       AuthType(0x5=SAM)<<4 | PageNumber(0)
//                                         -> Page Number MUST be 0 on page 0
//     [2]      Last Page Index            *** SEPARATE OCTET *** (high nibble 0)
//     [3]      Length                     total SAM Auth Data octets (all pages)
//     [4..7]   Timestamp (LE)             ASTM epoch 2019-01-01 (RFC §3.2.4.3)
//     [8..24]  Authentication Data        first 17 octets of SAM data
//
//   Page N>0:
//     [0]      0x22
//     [1]      0x5N                       AuthType(0x5)<<4 | PageNumber(N)
//                                         -> AuthType present on EVERY page
//     [2..24]  Authentication Data        next 23 octets (zero padded on last)
//
// This fixes the two CRITICAL framing defects found in the audit:
//   Finding 1 - missing dedicated Last Page Index octet (length was at [2],
//               timestamp shifted to [3..6], page 0 carried 18 octets + stray
//               byte). Now LPI is its own octet and page 0 carries exactly 17.
//   Finding 2 - continuation pages had AuthType nibble 0 (byte1 = 0x01..0x05).
//               Now every page header carries AuthType 0x5 (0x51..0x55).
// ---------------------------------------------------------------------------

// Convenience: write a uint32 little-endian (ASTM convention, RFC §3.2.4.3).
static inline void drip_put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)( v        & 0xFF);
    p[1] = (uint8_t)((v >>  8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// Number of Auth pages needed to carry 'auth_len' octets of SAM data.
// Page 0 holds 17 octets, each continuation page holds 23.
uint8_t drip_auth_pages_needed(uint8_t auth_len);

// Scatter 'auth_len' octets of SAM Authentication Data into ASTM Auth pages.
//
//   auth_data : the SAM Authentication Data (first octet is the SAM Type)
//   auth_len  : length of auth_data (becomes the ASTM Length field)
//   timestamp : value for the ASTM page-0 Timestamp header (DRIP epoch, LE)
//   out       : caller-provided [max_pages][25] buffer; fully zeroed by us
//   max_pages : capacity of out[]
//
// Returns the number of pages written, or 0 if auth_len does not fit in
// max_pages. All pages are zero-initialised, so the last page is null-padded
// (this also eliminates the stray uninitialised byte seen as 0xB3 in Finding 1).
uint8_t drip_auth_scatter(const uint8_t *auth_data, uint8_t auth_len,
                          uint32_t timestamp,
                          uint8_t out[][F3411_MSG_BYTES], uint8_t max_pages);

// ---------------------------------------------------------------------------
// DRIP Single Page FEC — RFC 9575 §5 / §5.1. LEGACY TRANSPORTS ONLY.
//
// RFC 9575 §6.1: FEC MUST be used over Legacy Transports (Bluetooth 4.x).
// RFC 9575 §6.2: FEC MUST NOT be used in Message Packs, so the Wi-Fi path keeps
//                calling drip_auth_scatter() above, unchanged.
//
// What this adds to the drip_auth_scatter() layout (RFC 9575 Figure 2 +
// Figure 11), viewing the 23-octet Authentication Payload of every page as one
// continuous stream:
//
//   [ Auth Headers (6) | Auth Data (Length) | ADL (1) | null pad | FEC (23) ]
//     LPI Len TS[4]                           ^ Additional Data Length
//
//   * ADL follows the last Auth Data octet. If Auth Data ends exactly at a
//     page boundary, ADL is the first octet of the next page (§5.2).
//   * Null padding fills the rest of that page, so the FEC starts on a new
//     page (§5.1 item 1).
//   * ADL = padding octets + 23 parity octets (§5.1 item 1, Figure 11: 33 =
//     10 pad + 23 FEC).
//   * Last Page Index = index of the FEC page, i.e. increased by the pages
//     needed for ADL, padding and FEC (§5.1 item 2). Length is NOT changed:
//     it still counts Auth Data only (the FEC is not signed, §5).
//   * Parity page payload = XOR of the 23-octet payloads of every data page,
//     page 0 included, starting from a 23-octet null pad (§5.1).
//   * Technical maximum 16 pages, LPI <= 15 (§3.2.1).
//
// Returns the number of pages written (data pages + 1 FEC page), or 0 if the
// result would exceed max_pages or 16 pages.
// ---------------------------------------------------------------------------
#define DRIP_AUTH_MAX_PAGES      16    // RFC 9575 §3.2.1: pages indexed 0..15

uint8_t drip_auth_scatter_fec(const uint8_t *auth_data, uint8_t auth_len,
                              uint32_t timestamp,
                              uint8_t out[][F3411_MSG_BYTES], uint8_t max_pages);
