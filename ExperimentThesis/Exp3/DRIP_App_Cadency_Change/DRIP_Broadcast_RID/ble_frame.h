#pragma once
#include <stdint.h>
#include <stddef.h>
#include "f3411_messages.h"   // F3411_MSG_BYTES

// ---------------------------------------------------------------------------
// ASTM F3411-22a Bluetooth LEGACY advertising payload — PURE framing.
//
// No BLE stack dependency and no I/O, so it can be checked off-target. The
// radio layer (ble_tx.*) hands these bytes to the controller as the complete
// advertising data of an ADV_NONCONN_IND PDU.
//
// Layout — ASTM F3411-22a §5.4.6.4 (BB40030), Table 14, "AD Info" onward:
//
//   [0]      0x1E      AD length = 30 octets (excluding this length octet)
//   [1]      0x16      AD type   = Service Data - 16-bit UUID
//   [2..3]   FA FF     UUID 0xFFFA (ASTM), little-endian on the wire
//   [4]      0x0D      AD Application Code = Open Drone ID
//   [5]      counter   Message Counter, ASTM §5.4.4.2 (per message type;
//                      identical on every page of one Auth message, BUR0060)
//   [6..30]  25 octets ONE ASTM message. Legacy carries no Message Pack
//                      (ASTM §5.4.5.22, RFC 9575 §6.2).
//
//   Total 31 octets = the Legacy advertising data maximum
//   (Bluetooth Core 5.0 Vol 6 Part B §2.3.1.3, cited by BB40010).
//
// The Preamble, Access Address, PDU header, AdvA and CRC rows of Table 14 are
// produced by the controller, not by this code.
//
// Origin: the framing idea follows ble_frame.* of the MOCK_DET_DRIP fork
// (flaviol-souza), which targeted BT5 Extended Advertising with a Message Pack.
// This version is re-written for Legacy: fixed 31-octet AD, one message.
// ---------------------------------------------------------------------------

#define ODID_BT_AD_LEN          0x1E    // Table 14: "Length 0x1E 30 Bytes"
#define ODID_BT_AD_TYPE_SVC16   0x16    // Service Data - 16-bit UUID
#define ODID_BT_UUID_LO         0xFA    // 0xFFFA little-endian
#define ODID_BT_UUID_HI         0xFF
#define ODID_BT_APP_CODE        0x0D    // Open Drone ID
#define ODID_BT_LEGACY_ADV_BYTES 31     // 1 + 0x1E

static_assert(ODID_BT_LEGACY_ADV_BYTES == 6 + F3411_MSG_BYTES,
              "Legacy AD must be header(6) + one 25-octet ASTM message");

// Build the 31-octet Legacy advertising data for one ASTM message.
//   msg     : exactly F3411_MSG_BYTES (25) octets
//   counter : ASTM §5.4.4.2 Message Counter for this message
//   out     : receives ODID_BT_LEGACY_ADV_BYTES (31) octets
void ble_build_legacy_adv(const uint8_t msg[F3411_MSG_BYTES], uint8_t counter,
                          uint8_t out[ODID_BT_LEGACY_ADV_BYTES]);
