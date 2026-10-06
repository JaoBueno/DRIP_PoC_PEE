#pragma once
#include <stdint.h>
#include "message_pack.h"
#include "f3411_messages.h"
#include "ble_tx.h"            // BlePut

// ---------------------------------------------------------------------------
// Runtime transport selector — Wi-Fi Beacon or Bluetooth Legacy.
//
// The fleet scheduler (drone_fleet.cpp) talks to the radio ONLY through this
// module, so which radio is on the air is a runtime choice made by the
// `radio wifi|bt` console command.
//
//   RID_RADIO_WIFI : ASTM F3411-22a §5.4.9 Wi-Fi Beacon, an Extended Transport.
//                    One Message Pack per beacon (beacon_tx_raw.*). This path is
//                    byte-identical to the build before this module existed.
//   RID_RADIO_BT   : ASTM F3411-22a §5.4.6 Bluetooth Legacy, a Legacy Transport.
//                    One 25-octet ASTM message per advertisement (ble_tx.*).
//
// Only one radio transmits at a time. Switching to BT stops Wi-Fi
// (esp_wifi_stop); switching back stops BLE advertising and restarts Wi-Fi.
// The Bluetooth stack is brought up on the FIRST switch to BT, not at boot, so
// a board whose controller fails to start still boots and runs Wi-Fi exactly
// as before.
// ---------------------------------------------------------------------------

enum RidRadio : uint8_t { RID_RADIO_WIFI = 0, RID_RADIO_BT = 1 };

// Bring up Wi-Fi as before (beacon_tx_raw_init). Call once in setup().
void rid_transport_init();

RidRadio    rid_transport_active();
const char *rid_transport_name(RidRadio r);

// Switch radios. Returns false, and leaves the current radio untouched, when
// the requested radio cannot start (BT controller failure is printed).
bool rid_transport_select(RidRadio r);

// ---- Wi-Fi (Extended Transport) ------------------------------------------
// No-ops while BT is active.
void rid_transport_send_pack(uint8_t slot, const MessagePack *pack, uint8_t msg_counter);
void rid_transport_repeat(uint8_t slot);

// ---- Bluetooth (Legacy Transport) ----------------------------------------
// BLE_PUT_BUSY while Wi-Fi is active; otherwise ble_tx_put()'s result.
BlePut rid_transport_put_legacy(uint8_t slot, const uint8_t msg[F3411_MSG_BYTES],
                                uint8_t counter);
bool rid_transport_legacy_busy();

// ---- either radio ----------------------------------------------------------
// Take slot `slot` off the air on the ACTIVE radio.
void rid_transport_stop(uint8_t slot);

// The address slot `slot` uses on the ACTIVE radio (Wi-Fi MAC or BLE static
// random address), 6 octets, most significant first. For logging.
const uint8_t *rid_transport_addr(uint8_t slot);
