#pragma once

// ---------------------------------------------------------------------------
// Project-wide build configuration.
//
// Put compile-time switches HERE (not in the .ino). In the Arduino build model
// each .cpp is compiled separately, and a #define in the .ino is visible only
// inside the .ino itself — it does NOT reach drip_registration.cpp etc. Defining
// the flag in this shared header (included by every unit that needs it) makes it
// consistent across all translation units.
//
// DRIP_TEST_BE : provision a self-consistent FAKE Apex/RAA/HDA Broadcast
//                Endorsement chain (drip_registration.*) for validation only.
//                *** Comment this line out for a production / flight image. ***
// ---------------------------------------------------------------------------

#define DRIP_TEST_BE

// ---------------------------------------------------------------------------
// DRIP_TEST_IMPERSONATION — the adversarial transmitter, for experiment E3.
//
//   *** LEAVE THIS COMMENTED OUT. Uncomment it only to build the adversarial
//   *** image, and flash the normal image back afterwards.
//
// WHAT IT DOES
//   One slot broadcasts ANOTHER slot's DET in the Basic ID message and in every
//   signed structure, retransmits that other slot's GENUINE DRIP Link, and
//   signs the evidence with ITS OWN key. It keeps its own MAC address.
//
// WHY IT IS A BUILD SWITCH AND NEVER A RUNTIME ONE
//   A console command that turns an aircraft into an impersonator is a weapon
//   left in the field. Making it a compile-time flag means the normal image
//   cannot be talked into this state, and the control capture described below
//   is what proves the normal image was not disturbed.
//
// WHAT THE OBSERVER IS EXPECTED TO REPORT
//   * the endorsement chain VERIFIES, because the retransmitted Link is the
//     victim's genuine one, signed by the HDA;
//   * the DET/key binding HOLDS, because that Link carries the victim's DET
//     together with the victim's public key;
//   * E-SIG-01 on the impersonator's Wrapper, and E-MAN-01 on its Manifest,
//     because the evidence was signed with a key that does not belong to the
//     DET it claims;
//   * W-MAC-02, because one DET now arrives from two transmitter addresses.
//
//   That combination is the point of the experiment: everything a chain of
//   endorsements can establish still holds, and the aircraft is still rejected,
//   because possession of the private key is what the evidence signature tests
//   and the impersonator does not have it.
//
// HOW TO RUN IT
//   1. Build and capture with this commented out. That is the control.
//   2. Uncomment, set the two slots below, rebuild, capture again.
//   3. Comment it out again and rebuild before any other use.
//   Both slots must be inside the active fleet size, so run at least
//   `fleet 2` on the console. If they are not, the firmware says so at boot
//   and transmits normally.
// ---------------------------------------------------------------------------

// #define DRIP_TEST_IMPERSONATION

// Which slot lies, and whose identity it claims. Ignored unless the switch
// above is uncommented.
#define DRIP_IMPERSONATOR_SLOT   1u   // this slot signs with its own key
#define DRIP_IMPERSONATED_SLOT   0u   // ...while claiming this slot's DET

#if defined(DRIP_TEST_IMPERSONATION) && \
    (DRIP_IMPERSONATOR_SLOT == DRIP_IMPERSONATED_SLOT)
#error "drip_config.h: the impersonator and the impersonated slot must differ, \
or the build is simply the normal image."
#endif
#if defined(DRIP_TEST_IMPERSONATION) && !defined(DRIP_TEST_BE)
#error "drip_config.h: DRIP_TEST_IMPERSONATION needs DRIP_TEST_BE, because the \
experiment retransmits the victim's endorsement and there is none without it."
#endif

// ---------------------------------------------------------------------------
// Bluetooth LEGACY transport (runtime-selectable with the `radio bt` command).
//
// The board is an ESP32-D0WD-V3: Bluetooth 4.2, no BLE 5.0 (measured with
// BT_Capability_Check). So the only ASTM F3411-22a Bluetooth method it can
// implement is Legacy advertising, §5.4.6. BT5 Long Range (§5.4.7) is not
// possible on this silicon.
//
// DOCUMENTED DIVERGENCE: RFC 9575 §3.2.4.1 notes that CAAs mandate BT 4.x AND
// 5.x transmitted simultaneously. This bench sends 4.x only, because the
// hardware has no 5.x radio.
//
// The two timing values below are BENCH PARAMETERS, not values taken from
// ASTM or the RFCs. They must be confirmed on hardware by counting adverts
// per second at the sniffer (`radio status` prints what the transmitter did).
// ---------------------------------------------------------------------------

// How long each ASTM message stays on the air before the advertising data is
// replaced by the next one (boot value; `radio slot <ms>` changes it at
// runtime). Must exceed one advertising interval plus the 0..10 ms advDelay
// the controller adds, or a message may never be sent.
// Budget: 18 messages per drone per second (RFC 9575 §6.4 schedule with Self
// ID and Operator ID). With DRIP_BLE_FLEET_MAX = 1, 30 ms uses 540 ms of each
// second; up to ~55 ms would still fit one drone. 30 ms equals 20 ms interval
// + 10 ms maximum advDelay: NO MARGIN per message. It is the starting point
// of the bench sweep (COMMANDS.md §1.7), not a validated value.
#define DRIP_BLE_ADV_SLOT_MS      30

// Advertising interval, in Bluetooth units of 0.625 ms (boot value;
// `radio int <units>` changes it at runtime). 0x20 = 20 ms, the lowest value
// the HCI command accepts. The Bluetooth 4.2 Core specification sets 100 ms as
// the minimum for non-connectable advertising; whether this BT 4.2 controller
// accepts and USES 20 ms is exactly what the bench must confirm: a rejection
// is printed at `radio bt`, a silent increase is visible only on the air
// (bt_timing.py, "real interval").
#define DRIP_BLE_ADV_INT_UNITS    0x20

// Drones allowed in the fleet while BT is active. Author decision
// 2026-09-29 (after Self ID and Operator ID were added): 1 drone. The Legacy
// second is now 18 messages per drone; 2 drones would need 36 x 30 ms = 1.08 s
// per second. With one drone the second takes 18 x 30 ms = 540 ms.
#define DRIP_BLE_FLEET_MAX        1

// ---------------------------------------------------------------------------
// "Other ASTM Messages" for the Bluetooth Legacy schedule — TEST VALUES.
//
// RFC 9575 §6.4 recommends, under Legacy Transport, one set of "other ASTM
// Messages" per second besides Basic ID / Location / System; given the ASTM
// message types, that means Self ID (0x3) and Operator ID (0x5), which is also
// what RFC 9575 Appendix B Figure 13 uses. Sent on BLUETOOTH ONLY: §6.4 does
// not ask for them under Extended Transport, and the Wi-Fi packs stay
// byte-identical.
//
// These values are FABRICATED for the bench, like the test RAA/HDA chain. They
// are the same values the Observer's reference encoder uses
// (make_vectors.py self_id() / operator_id()), so transmitter and test vectors
// agree. No CAA issued "OPERATOR-TEST-01". Replace both for any real use.
//   Self ID     : ASTM F3411-22a Table 10. Type 0 = Text Description; the
//                 text is Table 10's own example. Max 23 ASCII characters.
//   Operator ID : ASTM F3411-22a Table 12. Type 0 = Operator ID. Max 20 ASCII
//                 characters.
// Every drone sends the same values: one operator flying the whole fleet.
// ---------------------------------------------------------------------------
#define DRIP_TEST_SELF_ID_TYPE      0
#define DRIP_TEST_SELF_ID_TEXT      "DronesRus:Survey"
#define DRIP_TEST_OPERATOR_ID_TYPE  0
#define DRIP_TEST_OPERATOR_ID       "OPERATOR-TEST-01"

