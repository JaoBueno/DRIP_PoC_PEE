#pragma once
#include <stdint.h>
#include "det_generator.h"
#include "drone_playback.h"
#include "drip_manifest.h"
#include "drip_link.h"         // DRIP_LINK_FEC_PAGES (Bluetooth Legacy Link paging)

// ---------------------------------------------------------------------------
// Virtual drone fleet — bench emulator
//
// Runs 1..FLEET_MAX independent virtual UAs on ONE ESP32. Each drone has:
//   * its own identity  (DETIdentity, det_generator.h IDENTITY_TABLE slot)
//   * its own MAC       (beacon_tx_raw.h SLOT_MAC — a real, distinct transmitter)
//   * its own track     (PlaybackState — its own flight and its own pacing)
//   * its own DRIP state(DRIPManifestState — its own Prev/Curr hash chain,
//                        RFC 9575 §4.4.2 — and its own BE:HDA,UA leaf)
//   * its own counters  (ASTM §5.4.4.2 Message Pack counter; 802.11 sequence)
//
// N = 1 is the degenerate case and reproduces the original single-drone PoC
// exactly: slot 0 IS the original identity/DET, and the focused-slot commands
// below are the original commands.
//
// ---------------------------------------------------------------------------
// TIMING MODEL  (why there are two rates)
//
//   PACK CONTENT : 3 Hz per drone — a full A(Wrapper)/B(Link)/C(Manifest)
//                  rotation per ~1 s, unchanged from the single-drone PoC.
//                  ASTM §5.4.4.1 (BUR0010) requires dynamic messages at least
//                  every BCMinUasLocRefreshRate = 1 s; every cycle carries
//                  Basic ID + Location, so 3 Hz gives 3x margin per drone.
//
//   BEACON FRAME : ~10 Hz per drone — the SAME pack is re-transmitted with an
//                  unchanged Message Counter. ASTM §5.4.4.2 (BUR0050): "If the
//                  data being transmitted has not changed, incrementing the
//                  Message Counter is optional."
//                  This is not gold-plating: the old AP path got this for free
//                  (the AP beaconed ~10 Hz over an IE refreshed at 3 Hz).
//                  Sending each pack only once made the drones flicker in and
//                  out of channel-hopping scanners (measured on the bench:
//                  ~100 ms dwell vs a 333 ms beacon => ~30% capture chance).
//                  It also matches the 100 TU Beacon Interval we advertise.
//
//   PHASE STAGGER: drone i's pack rebuild is offset by i * (333 ms / N), and it
//                  starts at cycle phase i. Two consequences:
//                    1. at most ONE drone rebuilds (and therefore signs) at any
//                       instant — the Ed25519 cost never stacks up in one slot;
//                    2. the drones are not all transmitting Wrappers at once,
//                       which is what independent aircraft actually look like.
//
// Airtime at N=3: 3 drones x 10 Hz x ~300 B ~= 7% of channel 6. Fine.
//
// ---------------------------------------------------------------------------
// RAISING THE DRONE COUNT ABOVE 3
//   FLEET_MAX below is capped at 3 by agreed scope. To go higher you must also:
//     1. add identity rows      -> det_generator.cpp IDENTITY_TABLE
//                                  + DET_IDENTITY_SLOTS in det_generator.h
//     2. add per-drone MACs     -> beacon_tx_raw.cpp SLOT_MAC
//     3. re-check the airtime and the Ed25519 budget: N drones x 10 Hz beacons,
//        and each drone still needs a signature every ~333 ms.
// ---------------------------------------------------------------------------

#define FLEET_MAX               3      // <-- agreed scope cap; see note above

#define FLEET_PACK_PERIOD_MS  1000      // per drone: 3 Hz pack rebuild (A/B/C)
#define FLEET_BEACON_PERIOD_MS 500     // per drone: ~10 Hz beacon repeat (100 TU)

// One virtual UA.
struct VirtualDrone {
    DETIdentity       id;            // identity + signing key (slot-fixed)
    PlaybackState     track;         // independent flight cursor
    DRIPManifestState manifest;      // independent RFC 9575 §4.4 hash chain
    uint8_t           msg_counter;   // ASTM §5.4.4.2 Message Pack counter
    uint32_t          cycle;         // own A/B/C phase counter
    uint32_t          next_pack_ms;  // when this drone next rebuilds its pack
    uint32_t          next_beacon_ms;// when this drone next re-beacons
    bool              active;        // provisioned and in the fleet
    bool              off_air;       // finished/stopped -> beacons ceased

    // ---- Bluetooth Legacy only (RFC 9575 §6.4 schedule, drone_fleet.cpp) ----
    // ASTM §5.4.4.2 (BUR0050): one Message Counter PER MESSAGE TYPE on Legacy.
    uint8_t           ctr_basic;     // Basic ID
    uint8_t           ctr_loc;       // Location/Vector
    uint8_t           ctr_sys;       // System
    uint8_t           ctr_self;      // Self ID      (session 3, test value)
    uint8_t           ctr_op;        // Operator ID  (session 3, test value)
    uint8_t           ctr_auth;      // next value for a new Authentication message
    uint8_t           bt_step;       // position in the per-second schedule
    uint32_t          bt_period_ms;  // millis() when the current second started
    uint16_t          bt_last_period;// ms between this drone's last two second-starts
    // The FEC-protected Link is sent one page per second (RFC 9575 §6.4), so
    // its pages and their shared counter (BUR0060) persist across seconds.
    uint8_t           link_pages[DRIP_LINK_FEC_PAGES][F3411_MSG_BYTES];
    uint8_t           link_npages;   // 0 = no Link built yet
    uint8_t           link_cursor;   // next page to send
    uint8_t           link_counter;  // counter shared by all pages of this Link
};

// Load identities, provision the trust chain, and start with ONE drone on
// flight 0 (i.e. exactly the original single-drone PoC). Call once in setup(),
// after beacon_tx_raw_init().
void fleet_init();

// Drive the fleet. Call from loop() with millis(); returns immediately.
// Non-blocking: it only acts on drones whose next_pack_ms / next_beacon_ms
// deadline has passed.
void fleet_tick(uint32_t now_ms);

// Poll Serial for a command. Call once per loop().
//
//   fleet <1..3>              n drones, flights auto-assigned 0..n-1
//   fleet <n> same <flight>   n drones, all replaying the same flight
//   fleet set <slot> <flight> assign one slot's flight
//   fleet list                slot | MAC | DET | flight | phase | point
//   focus <slot>              legacy commands below target this slot
//   debug off|on|<slot>       pack hex dump: off, focused drone, or that drone
//
//   list | info | next | reset | stop | <number>
//                             unchanged single-drone commands; they act on the
//                             FOCUSED slot (default 0), so with `fleet 1` the
//                             console behaves exactly as it always did.
//
//   time                      show the board's clock (Unix, UTC, DRIP epoch) and
//                             whether it was set
//   time <unix>               set the clock: <unix> = whole seconds since
//                             1970-01-01T00:00:00Z (UTC), e.g. time 1790800260.
//                             Re-signs the endorsement chain so new
//                             endorsements carry the real date (RFC 9575
//                             §3.2.4.3). Rejected before 2024-01-01.
//
//   identity                  which identity the focused slot broadcasts, and the list
//   identity <0..5>           make the focused slot broadcast that identity
//                             (det_generator.h): 0-2 valid, 3 malformed DET,
//                             4 chain C (air-only), 5 bad endorsement signature.
//                             Refused if another slot already uses it.
//
//   radio | radio status      active transport and Bluetooth counters
//   radio wifi                Wi-Fi Beacon, ASTM F3411-22a §5.4.9 (default)
//   radio bt                  Bluetooth Legacy, ASTM F3411-22a §5.4.6
//                             (refused while the fleet has more than
//                              DRIP_BLE_FLEET_MAX drones)
void fleet_cmd();

// Print the board's clock: Unix, UTC, DRIP epoch, and whether `time` set it.
void fleet_print_time();
