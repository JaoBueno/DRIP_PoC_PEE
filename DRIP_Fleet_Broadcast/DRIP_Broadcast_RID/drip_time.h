#pragma once
#include <Arduino.h>          // required for millis()
#include "f3411_messages.h"   // for DRIP_EPOCH / SIM_DRIP_TIME_BASE constants

// Returns current time in the DRIP epoch (seconds since 2019-01-01 00:00:00 UTC).
// RFC 9575 §3.2.4.3: all authentication timestamps use this epoch.
//
// SIM_DRIP_TIME_BASE is only the BOOT value now (2026-01-01). Set the real time
// at runtime with the console command `time <unix>` (see below); editing the
// constant and reflashing is no longer needed.
//
// THIS IS THE ONLY CLOCK IN THE FIRMWARE. Every timestamp the board emits
// derives from it: the DRIP VNB and VNA, the Authentication header timestamp,
// the ASTM System message timestamp, and, since
// DRONE_REPLAY_RECORDED_TIME became 0, the ASTM Location message timestamp as
// well. Keeping one source is what makes those four agree.
//
// RUNTIME TIME SETTING (session 3, 2026-09-30)
// The board has no RTC, GNSS or network time. The base used to be the
// compile-time constant SIM_DRIP_TIME_BASE only, so every endorsement was
// signed with the build date and an Observer using real time correctly
// reported E-LINK-04 (RFC 9575 §3.2.4.3). The base is now a VARIABLE that starts
// at SIM_DRIP_TIME_BASE and is replaced by the `time <unix>` console command
// (drone_fleet.cpp). It is still the only clock: drip_timestamp() is unchanged
// for every caller, only where its base comes from changed.
// A reset returns to SIM_DRIP_TIME_BASE until the next `time` command.

// Earliest Unix time `time` accepts: 2024-01-01T00:00:00Z. Anything earlier is
// certainly a typing error, and would also give endorsements that expired
// long ago.
#define DRIP_TIME_MIN_UNIX   1704067200UL

// C++17 inline variables: one definition shared by every translation unit.
inline uint32_t g_drip_time_base   = SIM_DRIP_TIME_BASE;   // DRIP-epoch seconds at millis()=0
inline bool     g_drip_time_synced = false;                // true once `time` succeeded

inline uint32_t drip_timestamp() {
    return g_drip_time_base + (uint32_t)(millis() / 1000UL);
}

// Set the clock from a Unix time (seconds since 1970-01-01T00:00:00Z).
// Returns false, changing nothing, if unix_s is before DRIP_TIME_MIN_UNIX.
inline bool drip_time_set_unix(uint32_t unix_s) {
    if (unix_s < DRIP_TIME_MIN_UNIX) return false;
    const uint32_t drip_now = unix_s - DRIP_EPOCH_UNIX_S;  // RFC 9575 §3.2.4.3 epoch
    g_drip_time_base   = drip_now - (uint32_t)(millis() / 1000UL);
    g_drip_time_synced = true;
    return true;
}

inline bool drip_time_synced() { return g_drip_time_synced; }
