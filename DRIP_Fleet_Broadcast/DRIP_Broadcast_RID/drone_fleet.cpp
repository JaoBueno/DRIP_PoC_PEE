#include "drone_fleet.h"
#include "drip_config.h"
#include "rid_transport.h"     // runtime Wi-Fi / Bluetooth selection (was beacon_tx_raw.h)
#include "drip_auth_page.h"    // DRIP_AUTH_MAX_PAGES (Bluetooth Legacy page queue)
#include "ble_tx.h"            // ble_tx_puts()/ble_tx_errors() for `radio status`
#include "f3411_messages.h"
#include "message_pack.h"
#include "drip_time.h"
#include "drip_auth.h"
#include "drip_link.h"
#include "drip_manifest.h"
#include "drip_registration.h"
#include "drip_debug.h"
#include <Arduino.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>              // gmtime_r for the `time` command (session 3)

// ---------------------------------------------------------------------------
// Fleet state
// ---------------------------------------------------------------------------
static VirtualDrone g_fleet[FLEET_MAX];
static uint8_t      g_n     = 1;   // drones currently in the fleet
static uint8_t      g_focus = 0;   // slot the legacy commands act on

// Which slot's pack gets hex-dumped. -1 = none.
// See the bandwidth note in drip_debug.h: at 115200 baud a single drone's dump
// already eats ~90% of the link, so only ONE drone can ever be dumped.
static int8_t       g_debug_slot = -1;

// DRIP epoch -> Unix epoch offset (2019-01-01T00:00:00Z), as the .ino used.
#define DRIP_EPOCH_UNIX_OFFSET   1546300800u

// ---------------------------------------------------------------------------
// Bluetooth Legacy scheduler state (fleet_bt_*). Unused while Wi-Fi is active.
//
// Legacy carries ONE 25-octet message per advertisement, so a drone's second
// is a sequence of messages rather than one pack. Each message is queued here
// and put on the air for one slot (g_bt_slot_ms); a multi-page Authentication
// message (the Manifest) is queued page by page.
// ---------------------------------------------------------------------------
struct BtItem {
    uint8_t msg[F3411_MSG_BYTES];
    uint8_t counter;                       // ASTM §5.4.4.2 counter for this message
};
static BtItem   g_btq[DRIP_AUTH_MAX_PAGES];
static uint8_t  g_btq_n     = 0;           // items queued
static uint8_t  g_btq_next  = 0;           // next item to put on the air
static uint8_t  g_btq_slot  = 0;           // drone the queue belongs to
static uint32_t g_bt_next_slot_ms = 0;     // when the current message may be replaced
static uint32_t g_bt_put_fail     = 0;     // puts that failed with a GAP error, retried
static uint32_t g_bt_overruns     = 0;     // drone-seconds whose schedule took > 1 s + 1 slot
static bool     g_bt_nolink_warned = false;
// Runtime-adjustable slot (`radio slot <ms>`); drip_config.h gives the boot value.
static uint16_t g_bt_slot_ms      = DRIP_BLE_ADV_SLOT_MS;
// Burst scheduling: one drone sends its whole second before the next drone
// starts, so the advertising address changes once per drone per second rather
// than once per message. -1 = no burst in progress.
static int8_t   g_bt_burst        = -1;
static uint8_t  g_bt_rr           = 0;     // next drone to consider (round robin)

static void fleet_bt_reset(uint32_t now);    // defined below fleet_build_and_send
static void fleet_bt_tick(uint32_t now);
static void fleet_radio_status();

// ---------------------------------------------------------------------------
// Provision one slot: identity, track, manifest chain, counters, phase.
// ---------------------------------------------------------------------------
// Which identity (row of det_generator.cpp IDENTITY_TABLE) each radio slot
// broadcasts. Default: slot i = identity i, as before session 3. Changed at
// runtime by `identity <0..5>` for the focused slot, and kept across `fleet`
// resizes.
static uint8_t g_slot_ident[FLEET_MAX] = {0, 1, 2};

static bool fleet_provision(uint8_t slot, uint16_t flight) {
    VirtualDrone *d = &g_fleet[slot];
    memset(d, 0, sizeof(*d));

    // Identity is chosen per SLOT (g_slot_ident), not per flight - that is what
    // lets two drones fly the same recorded track under different DETs.
    if (!det_load_identity(g_slot_ident[slot], d->id)) {
        Serial.printf("[Fleet] slot %u: no identity %u in the table\n",
                      (unsigned)slot, (unsigned)g_slot_ident[slot]);
        return false;
    }
    if (!drone_playback_init(&d->track, flight)) {
        Serial.printf("[Fleet] slot %u: cannot select flight %u\n",
                      (unsigned)slot, flight);
        return false;
    }
    // Each UA owns its Prev/Curr Manifest hash chain (RFC 9575 §4.4.2). Seeded
    // from the hardware RNG, so two drones never share a chain.
    drip_manifest_init(&d->manifest);

    d->msg_counter = 0;
    d->cycle       = slot;    // PHASE STAGGER: drone i starts at phase i
    d->active      = true;
    d->off_air     = false;
    return true;
}

// Re-sign the BE chain for the current fleet. RFC 9575 §6.4.2: every UA needs
// its own BE:HDA,UA, so this must run whenever the fleet's membership changes.
static bool g_reg_first = true;   // first chain signing prints in full

static void fleet_reg_refresh() {
#ifdef DRIP_TEST_BE
    DETIdentity ids[FLEET_MAX];
    for (uint8_t i = 0; i < g_n; i++) ids[i] = g_fleet[i].id;
    // Full detail on the FIRST signing (the "this chain is fake" warning and
    // the anchor DETs must always be on the record at boot), and whenever the
    // operator has asked for debug. Every later re-sign — one per `fleet` /
    // `fleet set` — collapses to a single line so it does not bury the
    // command that triggered it.
    drip_reg_init_fleet(ids, g_n, g_reg_first || g_debug_slot >= 0);
    g_reg_first = false;
#endif
}

// Spread the drones' pack rebuilds evenly across the 333 ms period so that at
// most one Ed25519 signature is in flight at any instant.
static void fleet_restagger(uint32_t now) {
    uint32_t step = (g_n > 0) ? (FLEET_PACK_PERIOD_MS / g_n) : FLEET_PACK_PERIOD_MS;
    for (uint8_t i = 0; i < g_n; i++) {
        g_fleet[i].next_pack_ms   = now + (uint32_t)i * step;
        g_fleet[i].next_beacon_ms = now + (uint32_t)i * step;
    }
}

// ---------------------------------------------------------------------------
static void fleet_list() {
    Serial.println("[Fleet] slot  MAC                DET                               id  flight  phase  point");
    for (uint8_t s = 0; s < g_n; s++) {
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;
        const uint8_t *m = rid_transport_addr(s);   // address on the ACTIVE radio
        Serial.printf("   %s%u   %02X:%02X:%02X:%02X:%02X:%02X  ",
                      (s == g_focus) ? ">" : " ", (unsigned)s,
                      m[0], m[1], m[2], m[3], m[4], m[5]);
        for (int i = 0; i < DET_BYTES; i++) Serial.printf("%02X", d->id.det[i]);
        Serial.printf("  %u  %5u   %c    %5u/%u%s\n",
                      (unsigned)d->id.index,
                      d->track.flight,
                      "ABC"[d->cycle % 3],
                      d->track.idx, drone_playback_points(d->track.flight),
                      d->off_air ? "  [off air]" : "");
    }
    Serial.printf("[Fleet] %u drone(s); focus=slot %u; pack dump=%s\n",
                  (unsigned)g_n, (unsigned)g_focus,
                  (g_debug_slot < 0) ? "off" : "on");
    Serial.printf("[Fleet] radio: %s\n", rid_transport_name(rid_transport_active()));
    if (g_debug_slot >= 0) Serial.printf("[Fleet] dumping slot %d\n", (int)g_debug_slot);
}

// ---------------------------------------------------------------------------
// Resize / re-assign the fleet.
//   same == true  -> every drone replays `same_flight`
//   same == false -> drone i replays flight i (wrapped to the table size)
// ---------------------------------------------------------------------------
static void fleet_set_size(uint8_t n, bool same, uint16_t same_flight) {
    if (n < 1 || n > FLEET_MAX) {
        Serial.printf("[Fleet] n must be 1..%u (FLEET_MAX in drone_fleet.h)\n",
                      (unsigned)FLEET_MAX);
        return;
    }
    if (!drone_playback_available()) {
        Serial.println("[Fleet] no flights compiled in (drone_data.h) — cannot start");
        return;
    }
    // Bluetooth Legacy carries one message per advertisement on one
    // advertising set; the fleet size there is capped until measured.
    if (rid_transport_active() == RID_RADIO_BT && n > DRIP_BLE_FLEET_MAX) {
        Serial.printf("[Fleet] Bluetooth is active: at most %u drone(s) "
                      "(DRIP_BLE_FLEET_MAX). Use 'radio wifi' first.\n",
                      (unsigned)DRIP_BLE_FLEET_MAX);
        return;
    }
    const uint16_t nflights = drone_playback_count();
    if (same && same_flight >= nflights) {
        Serial.printf("[Fleet] flight %u out of range (0..%u)\n",
                      same_flight, nflights - 1);
        return;
    }

    // Take the drones being removed off the air BEFORE forgetting them.
    for (uint8_t i = n; i < FLEET_MAX; i++) {
        if (g_fleet[i].active) rid_transport_stop(i);
        g_fleet[i].active = false;
    }
    for (uint8_t i = 0; i < n; i++) {
        uint16_t f = same ? same_flight : (uint16_t)(i % nflights);
        fleet_provision(i, f);
    }

    g_n = n;
    if (g_focus >= g_n) g_focus = 0;

    // With more than one drone the serial link cannot carry the hex dumps
    // (drip_debug.h bandwidth note) — turning it off is the difference between
    // a working scheduler and one that blocks in Serial.print().
    if (g_n > 1 && g_debug_slot >= 0) {
        g_debug_slot = -1;
        Serial.println("[Fleet] pack dump AUTO-DISABLED: at 115200 baud one drone's "
                       "dump already uses ~90% of the link, so >1 drone would stall "
                       "the scheduler. Use 'debug <slot>' to dump exactly one.");
    }

    fleet_reg_refresh();
    fleet_restagger(millis());
    if (rid_transport_active() == RID_RADIO_BT) fleet_bt_reset(millis());
    fleet_list();
}

// ---------------------------------------------------------------------------
// Build and transmit ONE drone's pack. This is the original .ino A/B/C cycle,
// unchanged in substance — only the singletons became per-drone fields.
// ---------------------------------------------------------------------------
#ifdef DRIP_TEST_IMPERSONATION
// ---------------------------------------------------------------------------
// The adversarial transmitter (drip_config.h, experiment E3).
//
// Returns the identity the given slot should BROADCAST, and through
// `link_slot` the slot whose endorsement it should retransmit.
//
// For the impersonator the returned identity carries the VICTIM's DET with the
// IMPERSONATOR's own key pair, which is the whole of the attack: every field
// that names an identity says the victim, and every signature is made with a
// key that does not derive it. Nothing else in the build changes, so the MAC
// address stays the impersonator's own and one DET reaches the air from two
// addresses.
//
// It degrades to the normal identity when either slot is outside the active
// fleet, because an impersonation of a drone that is not flying would look
// like an ordinary unknown aircraft and prove nothing.
// ---------------------------------------------------------------------------
static DETIdentity fleet_broadcast_identity(uint8_t slot, const VirtualDrone *d,
                                            uint8_t *link_slot) {
    *link_slot = slot;
    if (slot != DRIP_IMPERSONATOR_SLOT)             return d->id;
    if (DRIP_IMPERSONATOR_SLOT >= g_n)              return d->id;
    if (DRIP_IMPERSONATED_SLOT >= g_n)              return d->id;
    if (!g_fleet[DRIP_IMPERSONATED_SLOT].active)    return d->id;

    DETIdentity claimed = d->id;                    // keep OUR key pair
    memcpy(claimed.det, g_fleet[DRIP_IMPERSONATED_SLOT].id.det, DET_BYTES);
    *link_slot = DRIP_IMPERSONATED_SLOT;            // retransmit THEIR endorsement
    return claimed;
}
#endif

static void fleet_build_and_send(uint8_t slot, VirtualDrone *d) {
    const uint8_t phase = (uint8_t)(d->cycle % 3);

    // Which identity goes on the air, and whose endorsement accompanies it.
    // Identical to this drone's own in every normal build.
    uint8_t link_slot = slot;
#ifdef DRIP_TEST_IMPERSONATION
    const DETIdentity tx_id = fleet_broadcast_identity(slot, d, &link_slot);
#else
    const DETIdentity &tx_id = d->id;
#endif

    // Gate the hex dump to at most one drone (see drip_debug.h).
    drip_debug_set_enabled(g_debug_slot == (int8_t)slot);

    // Position: recorded track, paced by the recorded timestamps. The clock
    // passed here is the one drip_timestamp() drives, converted to the Unix
    // epoch, and with DRONE_REPLAY_RECORDED_TIME at 0 it is what the Location
    // message reports. Every timestamp in the resulting pack therefore comes
    // from that single clock.
    DronePosition pos = drone_playback_next(&d->track,
                                            drip_timestamp() + DRIP_EPOCH_UNIX_OFFSET,
                                            slot);

    uint8_t session_id[SESSION_ID_BYTES];
    det_to_session_id(tx_id.det, session_id);          // the DET we broadcast

    F3411BasicID  basic_id = f3411_build_basic_id(session_id);
    F3411Location location = f3411_build_location(pos);

    double op_lat, op_lon; float op_alt;
    drone_playback_get_launch(&d->track, &op_lat, &op_lon, &op_alt);
    F3411System system_msg = f3411_build_system(op_lat, op_lon, op_alt);

    // Common to all cycles: Basic ID + Location. System is added per-cycle
    // (A and C only — Cycle B has no room; see the CYCLE-B NOTE in the .ino).
    MessagePack pack;
    message_pack_init(&pack);
    message_pack_add(&pack, (const uint8_t *)&basic_id);
    message_pack_add(&pack, (const uint8_t *)&location);

    switch (phase) {

        // ---- Cycle A: DRIP Wrapper (RFC 9575 §4.3) ----
        case 0: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t wrapper[DRIP_WRAPPER_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t wrapper_pages = 0;
            // Signs with THIS drone's key and carries the DET we broadcast.
            // In a normal build those are the same identity.
            drip_wrapper_build(tx_id, &pack, wrapper, &wrapper_pages);
            for (uint8_t i = 0; i < wrapper_pages; i++)
                message_pack_add(&pack, wrapper[i]);

            drip_manifest_update_pack(&d->manifest, pack.buf,
                                      message_pack_bytes(&pack));
            break;
        }

        // ---- Cycle B: DRIP Link / Broadcast Endorsement (RFC 9575 §4.2) ----
        case 1: {
#ifdef DRIP_TEST_BE
            // This slot's own rotation cursor over its own chain.
            const BroadcastEndorsement *be = drip_reg_next_link(link_slot);
            uint8_t link[DRIP_LINK_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t link_pages = drip_link_build_be(be, link, DRIP_LINK_MAX_PAGES);
            for (uint8_t i = 0; i < link_pages; i++)
                message_pack_add(&pack, link[i]);   // 7 pages -> 2 + 7 = 9 msgs

            // The Manifest references BE:HDA,UA specifically (RFC §4.4.2), so
            // hash THIS drone's leaf regardless of which link went out.
            uint8_t hu_sam[DRIP_LINK_SAM_BYTES];
            uint8_t hu_len = drip_reg_hda_ua_sam(link_slot, hu_sam);
            drip_manifest_update_link(&d->manifest, hu_sam, hu_len);
#else
            Serial.println("[Link] No Broadcast Endorsement provisioned. "
                           "Define DRIP_TEST_BE (test) or load BE records (production).");
#endif
            break;
        }

        // ---- Cycle C: DRIP Manifest (RFC 9575 §4.4) ----
        case 2: {
            message_pack_add(&pack, (const uint8_t *)&system_msg);

            uint8_t manifest[DRIP_MANIFEST_MAX_PAGES][F3411_MSG_BYTES];
            uint8_t manifest_pages = 0;
            drip_manifest_build(&d->manifest, tx_id, manifest, &manifest_pages);
            for (uint8_t i = 0; i < manifest_pages; i++)
                message_pack_add(&pack, manifest[i]);
            break;
        }
    }

    const uint8_t tx_counter = d->msg_counter++;   // per-UA (ASTM §5.4.4.2)
    rid_transport_send_pack(slot, &pack, tx_counter);   // Wi-Fi only; see fleet_tick
    drip_debug_print_pack(&pack, tx_counter, phase, slot, tx_id.det);

    d->cycle++;
}


// ===========================================================================
// Bluetooth LEGACY scheduler — RFC 9575 §6.4, ASTM F3411-22a §5.4.6
//
// RFC 9575 §6.4 recommends, once per second under Legacy Transport:
//   * two sets of the ASTM messages the CAA requires (Basic ID, Location/
//     Vector, System),
//   * one set of other ASTM messages (Self ID, Operator ID),
//   * one FEC-protected DRIP Manifest authenticating the messages sent,
//   * one page of an FEC-protected DRIP Link.
// No Wrapper is sent (user decision, 2026-09-29; §6.4.1 makes it optional).
// Self ID and Operator ID carry TEST VALUES (drip_config.h).
//
// One second of one drone, in order (18 advertisements with a ~7-hash,
// 9-page Manifest):
//
//   BASIC LOC SYS SELF OPER  MANIFEST(p0..p8)  BASIC LOC SYS  LINK(1 page)
//
// * ORDER vs RFC 9575 Appendix B Figure 13: the RFC's informative example
//   sends both sets first and the Manifest after them. Here the Manifest sits
//   BETWEEN the sets, as before, so the two Location messages stay ~half a
//   second apart. With Figure 13's order they would be ~150 ms apart and the
//   gap to the next second's Location would approach the 1 s of BUR0010.
//
// * The Manifest follows a set of messages so that it hashes messages
//   ALREADY SENT (RFC 9575 §4.4: "hashes of previously sent ASTM Messages").
//   It covers everything sent since the previous Manifest: this second's
//   first set and the previous second's second set.
// * Location is built at the moment it is queued, so both sets carry a fresh
//   position; the two are ~0.5 s apart, inside the 1 s of ASTM §5.4.4.1
//   (BUR0010).
// * Counters: one per message type (ASTM §5.4.4.2, BUR0050). An Authentication
//   message takes a new counter value, and all its pages share it (BUR0060).
//   The Link keeps its value for the ~8 s its pages take, while Manifests in
//   between take new values: on Legacy the counter is also what correlates
//   pages to one message (RFC 9575 §5.2), so two interleaved Authentication
//   messages cannot share one value. The 8-bit counter wraps after 256 new
//   Authentication messages (~4 min), far longer than one Link takes.
// * A full rotation of the six-position BE schedule (drip_registration.*)
//   therefore takes 6 x 8 s = 48 s on Bluetooth, against ~6 s on Wi-Fi. That
//   is the direct cost of one Link page per second.
//
// SEVERAL DRONES. This board has ONE Legacy advertising set, so drones share
// it in time. DRIP_BLE_FLEET_MAX is 1 since Self ID and Operator ID were added
// (author decision 2026-09-29): the 18-message second of 2 drones would take
// 1.08 s at the 30 ms slot. The multi-drone machinery below is kept for when
// the bench measurement allows raising the limit:
// * BURSTS: a drone sends its whole second (18 messages) before the next drone
//   starts. The random address cannot change while advertising, so each change
//   costs a stop/set-address/start; bursts need one change per drone per
//   second instead of one per message.
// * STAGGER: drone i's second starts i x (1000 ms / n) after drone 0's.
// * BUDGET: 18 messages per drone per second. At the 30 ms slot one drone uses
//   540 ms of every second. `radio status` reports each drone's real period
//   and counts overruns; the sniffer and bt_timing.py measure the air.
// ===========================================================================
enum BtStep : uint8_t {
    BT_BASIC_A = 0, BT_LOC_A, BT_SYS_A, BT_SELF_ID, BT_OPERATOR_ID, BT_MANIFEST,
    BT_BASIC_B,     BT_LOC_B, BT_SYS_B, BT_LINK_PAGE,
    BT_STEPS
};

static void btq_push(const uint8_t *msg, uint8_t counter) {
    if (g_btq_n >= DRIP_AUTH_MAX_PAGES) return;          // cannot happen: max 16 pages
    memcpy(g_btq[g_btq_n].msg, msg, F3411_MSG_BYTES);
    g_btq[g_btq_n].counter = counter;
    g_btq_n++;
}

// Update the Manifest's DRIP Link hash from this slot's BE:HDA,UA, exactly as
// the Wi-Fi Cycle B does (RFC 9575 §4.4.2).
static void fleet_bt_refresh_link_hash(uint8_t link_slot, VirtualDrone *d) {
#ifdef DRIP_TEST_BE
    uint8_t hu_sam[DRIP_LINK_SAM_BYTES];
    uint8_t hu_len = drip_reg_hda_ua_sam(link_slot, hu_sam);
    if (hu_len) drip_manifest_update_link(&d->manifest, hu_sam, hu_len);
#else
    (void)link_slot; (void)d;
#endif
}

// Start every drone's Bluetooth schedule from the top. Called on `radio bt`
// and whenever the fleet or its endorsement chain changes while on BT.
// Drone i's first second starts i x (1000 ms / n) after drone 0's, the same
// stagger as on Wi-Fi, so the bursts do not queue behind each other.
static void fleet_bt_reset(uint32_t now) {
    g_btq_n = g_btq_next = 0;
    g_bt_next_slot_ms = now;
    g_bt_burst = -1;
    g_bt_rr    = 0;
    const uint32_t stagger = (g_n > 0) ? (FLEET_PACK_PERIOD_MS / g_n) : FLEET_PACK_PERIOD_MS;
    for (uint8_t s = 0; s < g_n; s++) {
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;
        uint8_t link_slot = s;
#ifdef DRIP_TEST_IMPERSONATION
        (void)fleet_broadcast_identity(s, d, &link_slot);
#endif
        // Idle, and "due" exactly at now + s x stagger (the tick starts a new
        // second when FLEET_PACK_PERIOD_MS has passed since bt_period_ms).
        d->bt_step        = BT_STEPS;
        d->bt_period_ms   = now + (uint32_t)s * stagger - FLEET_PACK_PERIOD_MS;
        d->bt_last_period = 0;
        d->link_npages  = 0;          // rebuild the Link from the current chain
        d->link_cursor  = 0;
        d->manifest.msg_hash_count = 0;
        fleet_bt_refresh_link_hash(link_slot, d);
    }
}

// Queue the next step of drone `slot`'s second.
static void fleet_bt_enqueue_step(uint8_t slot, VirtualDrone *d) {
    uint8_t link_slot = slot;
#ifdef DRIP_TEST_IMPERSONATION
    const DETIdentity tx_id = fleet_broadcast_identity(slot, d, &link_slot);
#else
    const DETIdentity &tx_id = d->id;
#endif
    drip_debug_set_enabled(g_debug_slot == (int8_t)slot);
    g_btq_n = g_btq_next = 0;
    g_btq_slot = slot;

    switch (d->bt_step) {
    case BT_BASIC_A:
    case BT_BASIC_B: {
        uint8_t session_id[SESSION_ID_BYTES];
        det_to_session_id(tx_id.det, session_id);
        F3411BasicID m = f3411_build_basic_id(session_id);
        btq_push((const uint8_t *)&m, d->ctr_basic++);
        break;
    }
    case BT_LOC_A:
    case BT_LOC_B: {
        // Same single clock as the Wi-Fi path (drip_time.h).
        DronePosition pos = drone_playback_next(&d->track,
                                                drip_timestamp() + DRIP_EPOCH_UNIX_OFFSET,
                                                slot);
        F3411Location m = f3411_build_location(pos);
        btq_push((const uint8_t *)&m, d->ctr_loc++);
        break;
    }
    case BT_SYS_A:
    case BT_SYS_B: {
        double op_lat, op_lon; float op_alt;
        drone_playback_get_launch(&d->track, &op_lat, &op_lon, &op_alt);
        F3411System m = f3411_build_system(op_lat, op_lon, op_alt);
        btq_push((const uint8_t *)&m, d->ctr_sys++);
        break;
    }
    case BT_SELF_ID: {
        // ASTM F3411-22a Table 10 — TEST VALUE (drip_config.h)
        F3411SelfID m = f3411_build_self_id(DRIP_TEST_SELF_ID_TYPE, DRIP_TEST_SELF_ID_TEXT);
        btq_push((const uint8_t *)&m, d->ctr_self++);
        break;
    }
    case BT_OPERATOR_ID: {
        // ASTM F3411-22a Table 12 — TEST VALUE (drip_config.h)
        F3411OperatorID m = f3411_build_operator_id(DRIP_TEST_OPERATOR_ID_TYPE,
                                                    DRIP_TEST_OPERATOR_ID);
        btq_push((const uint8_t *)&m, d->ctr_op++);
        break;
    }
    case BT_MANIFEST: {
        uint8_t pages[DRIP_AUTH_MAX_PAGES][F3411_MSG_BYTES];
        uint8_t np = 0;
        drip_manifest_build_legacy(&d->manifest, tx_id, pages, DRIP_AUTH_MAX_PAGES, &np);
        const uint8_t c = d->ctr_auth++;
        for (uint8_t i = 0; i < np; i++) btq_push(pages[i], c);
        break;
    }
    case BT_LINK_PAGE: {
#ifdef DRIP_TEST_BE
        if (d->link_cursor >= d->link_npages) {
            // Previous Link fully sent (or none yet): take the next BE of this
            // slot's rotation and page it with FEC.
            const BroadcastEndorsement *be = drip_reg_next_link(link_slot);
            d->link_npages  = be ? drip_link_build_be_fec(be, d->link_pages,
                                                          DRIP_LINK_FEC_PAGES) : 0;
            d->link_cursor  = 0;
            d->link_counter = d->ctr_auth++;
            fleet_bt_refresh_link_hash(link_slot, d);
        }
        if (d->link_cursor < d->link_npages)
            btq_push(d->link_pages[d->link_cursor++], d->link_counter);
#else
        if (!g_bt_nolink_warned) {
            Serial.println("[Link] No Broadcast Endorsement provisioned. "
                           "Define DRIP_TEST_BE (test) or load BE records (production).");
            g_bt_nolink_warned = true;
        }
#endif
        break;
    }
    default:
        break;
    }
}

// One advertising slot at a time: replace the advertised message when the
// current one has been on the air for g_bt_slot_ms.
static void fleet_bt_tick(uint32_t now) {
    if ((int32_t)(now - g_bt_next_slot_ms) < 0) return;
    if (rid_transport_legacy_busy()) return;

    // 1) Something queued: put it on the air.
    if (g_btq_next < g_btq_n) {
        const BtItem *it = &g_btq[g_btq_next];
        const BlePut r = rid_transport_put_legacy(g_btq_slot, it->msg, it->counter);
        if (r == BLE_PUT_SWITCHING || r == BLE_PUT_BUSY) {
            g_bt_next_slot_ms = now;              // retry as soon as the controller is free
            return;
        }
        if (r == BLE_PUT_ERROR) {
            g_bt_put_fail++;
            g_bt_next_slot_ms = now + g_bt_slot_ms;   // do not hammer a failing call
            return;
        }
        g_bt_next_slot_ms = now + g_bt_slot_ms;   // this message owns the next slot
        const uint8_t type = it->msg[0] >> 4;
        // Only messages that actually went out are hashed for the Manifest.
        if (type != F3411_TYPE_AUTH)
            drip_manifest_note_message(&g_fleet[g_btq_slot].manifest, it->msg);
        if (g_debug_slot == (int8_t)g_btq_slot) {
            if (type == F3411_TYPE_AUTH)
                Serial.printf("[BT] %lu ms  slot %u  cnt=%3u  Auth SAM page %u\n",
                              (unsigned long)now, (unsigned)g_btq_slot,
                              (unsigned)it->counter, (unsigned)(it->msg[1] & 0x0F));
            else
                Serial.printf("[BT] %lu ms  slot %u  cnt=%3u  type 0x%X\n",
                              (unsigned long)now, (unsigned)g_btq_slot,
                              (unsigned)it->counter, (unsigned)type);
        }
        g_btq_next++;
        return;
    }

    // 2) Queue empty: choose the drone whose step goes next.
    int8_t pick = -1;

    // 2a) Continue the burst in progress, if its drone is still flying.
    if (g_bt_burst >= 0 && g_bt_burst < (int8_t)g_n) {
        VirtualDrone *d = &g_fleet[g_bt_burst];
        if (d->active && !drone_playback_finished(&d->track) && d->bt_step < BT_STEPS)
            pick = g_bt_burst;
    }
    g_bt_burst = -1;

    // 2b) Otherwise start the second of the next drone that is due.
    for (uint8_t k = 0; pick < 0 && k < g_n; k++) {
        const uint8_t s = (uint8_t)((g_bt_rr + k) % g_n);
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;
        if (drone_playback_finished(&d->track)) {
            if (!d->off_air) { rid_transport_stop(s); d->off_air = true; }
            continue;
        }
        d->off_air = false;
        if (d->bt_step < BT_STEPS) { pick = s; break; }  // interrupted burst: resume
        const uint32_t took = now - d->bt_period_ms;
        if ((int32_t)took < (int32_t)FLEET_PACK_PERIOD_MS) continue;   // not due yet
        d->bt_last_period = (uint16_t)((took > 65535u) ? 65535u : took);
        if (took > FLEET_PACK_PERIOD_MS + g_bt_slot_ms) g_bt_overruns++;
        d->bt_period_ms = now;
        d->bt_step = 0;
        pick = s;
    }
    if (pick < 0) return;                             // nobody due: keep advertising

    g_bt_rr    = (uint8_t)((pick + 1) % g_n);
    g_bt_burst = pick;
    VirtualDrone *d = &g_fleet[pick];
    fleet_bt_enqueue_step((uint8_t)pick, d);
    d->bt_step++;
}

static void fleet_radio_status() {
    Serial.printf("[Radio] active: %s\n", rid_transport_name(rid_transport_active()));
    if (rid_transport_active() != RID_RADIO_BT) return;
    const uint16_t iv = ble_tx_interval();
    Serial.printf("[Radio] BT slot %u ms, adv interval 0x%X (%.2f ms), fleet max %u\n",
                  (unsigned)g_bt_slot_ms, (unsigned)iv, iv * 0.625f,
                  (unsigned)DRIP_BLE_FLEET_MAX);
    Serial.printf("[Radio] BT puts=%lu  address switches=%lu  put errors=%lu  GAP errors=%lu\n",
                  (unsigned long)ble_tx_puts(), (unsigned long)ble_tx_switches(),
                  (unsigned long)g_bt_put_fail, (unsigned long)ble_tx_errors());
    Serial.printf("[Radio] BT overruns(>1 s + 1 slot)=%lu\n", (unsigned long)g_bt_overruns);
    for (uint8_t s = 0; s < g_n; s++) {
        const VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;
        Serial.printf("[Radio] slot %u: last period=%u ms  step %u/%u  cnt basic=%u loc=%u "
                      "sys=%u self=%u oper=%u auth=%u  link page %u/%u (cnt %u)%s\n",
                      (unsigned)s, (unsigned)d->bt_last_period,
                      (unsigned)d->bt_step, (unsigned)BT_STEPS,
                      d->ctr_basic, d->ctr_loc, d->ctr_sys, d->ctr_self, d->ctr_op, d->ctr_auth,
                      d->link_cursor, d->link_npages, d->link_counter,
                      d->off_air ? "  [off air]" : "");
    }
}

// ---------------------------------------------------------------------------
void fleet_init() {
    memset(g_fleet, 0, sizeof(g_fleet));
    g_n = 1; g_focus = 0;

#ifdef DRIP_TEST_IMPERSONATION
    // Announced unconditionally and at boot. A capture taken from this image is
    // adversarial evidence, and nothing about the air interface says so, since
    // looking exactly like the victim is the point.
    Serial.println();
    Serial.println("***************************************************************");
    Serial.println("*** ADVERSARIAL IMAGE: DRIP_TEST_IMPERSONATION IS COMPILED IN.");
    Serial.printf ("*** Slot %u will broadcast slot %u's DET and sign with its own\n",
                   (unsigned)DRIP_IMPERSONATOR_SLOT,
                   (unsigned)DRIP_IMPERSONATED_SLOT);
    Serial.println("*** key. Expect E-SIG-01, E-MAN-01 and W-MAC-02 at the Observer.");
    Serial.println("*** Run at least 'fleet 2', or both slots are not on the air and");
    Serial.println("*** this image transmits normally.");
    Serial.println("*** Rebuild with the switch commented out for any other use.");
    Serial.println("***************************************************************");
    Serial.println();
#endif
    // Boot CLEAN: the console is for flying the drones. Per-cycle status from
    // the Wrapper/Manifest and the pack hex dump stay silent until asked for.
    // Signing WARN/ERROR lines are never gated, so a quiet console means
    // "everything is signing", not "no information".
    g_debug_slot = -1;

    if (!drone_playback_available()) {
        Serial.println("[Fleet] ERROR: drone_data.h contains no flights — nothing to fly.");
        Serial.println("[Fleet] (The old flight_sim fallback was dropped for the fleet: it is");
        Serial.println("[Fleet]  a stateless global route, so N drones would all sit on the");
        Serial.println("[Fleet]  same synthetic point — a degenerate multi-drone test.)");
        return;
    }

    fleet_provision(0, 0);
    fleet_reg_refresh();

    drip_debug_set_enabled(false);
    fleet_restagger(millis());

    Serial.println();
    drone_playback_list();
    fleet_list();
    Serial.println("[Fleet] console is QUIET by default — 'debug on' shows this drone's");
    Serial.println("        per-cycle Wrapper/Manifest detail + pack hex dump.");
    Serial.println("[Fleet] commands: fleet <1..3> | fleet <n> same <flight> |");
    Serial.println("                  fleet set <slot> <flight> | fleet list |");
    Serial.println("                  focus <slot> | debug off|on|<slot> |");
    Serial.println("                  list | info | next | reset | stop | <number> |");
    Serial.println("                  time | time <unix> | identity | identity <0..5> |");
    Serial.println("                  radio | radio wifi | radio bt |");
    Serial.println("                  radio slot <ms> | radio int <units>");
}

// ---------------------------------------------------------------------------
void fleet_tick(uint32_t now_ms) {
    // Bluetooth Legacy has its own per-message scheduler (RFC 9575 §6.4).
    if (rid_transport_active() == RID_RADIO_BT) { fleet_bt_tick(now_ms); return; }

    for (uint8_t s = 0; s < g_n; s++) {
        VirtualDrone *d = &g_fleet[s];
        if (!d->active) continue;

        // End of track (or 'stop'): this drone leaves the air. Nothing is built
        // or signed, its Manifest chain does not advance, its counter freezes.
        // Selecting a flight for it resumes transmission.
        if (drone_playback_finished(&d->track)) {
            if (!d->off_air) { rid_transport_stop(s); d->off_air = true; }
            continue;
        }
        d->off_air = false;

        // Signed comparison handles millis() wraparound (~49.7 days) correctly.
        if ((int32_t)(now_ms - d->next_pack_ms) >= 0) {
            fleet_build_and_send(s, d);
            // Re-arm from NOW rather than += period: if a cycle overruns we do
            // not want a burst of catch-up sends.
            d->next_pack_ms   = now_ms + FLEET_PACK_PERIOD_MS;
            d->next_beacon_ms = now_ms + FLEET_BEACON_PERIOD_MS;
        } else if ((int32_t)(now_ms - d->next_beacon_ms) >= 0) {
            // Same pack, same Message Counter — ASTM §5.4.4.2 (BUR0050) permits
            // repeating unchanged data. Only the 802.11 sequence advances.
            rid_transport_repeat(s);
            d->next_beacon_ms = now_ms + FLEET_BEACON_PERIOD_MS;
        }
    }
}

// ---------------------------------------------------------------------------
// Serial commands
// ---------------------------------------------------------------------------
static bool parse_u16(const char *s, uint16_t *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 0 || v > 65535) return false;
    *out = (uint16_t)v;
    return true;
}

// Print the board's clock. Public so setup() can report it at boot.
void fleet_print_time() {
    const uint32_t drip = drip_timestamp();
    time_t unix_s = (time_t)drip + (time_t)DRIP_EPOCH_UNIX_S;
    struct tm tm_utc;
    gmtime_r(&unix_s, &tm_utc);
    Serial.printf("[Time] unix=%lu  %04d-%02d-%02dT%02d:%02d:%02dZ  DRIP=%lu  %s\n",
                  (unsigned long)unix_s,
                  tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                  tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec,
                  (unsigned long)drip,
                  drip_time_synced() ? "(set by the 'time' command)"
                                     : "(NOT set - build default; type: time <unix>)");
}

void fleet_cmd() {
    if (!Serial.available()) return;

    char buf[48];
    size_t n = Serial.readBytesUntil('\n', buf, sizeof(buf) - 1);
    buf[n] = '\0';
    while (n && (buf[n - 1] == '\r' || buf[n - 1] == ' ')) buf[--n] = '\0';
    if (n == 0) return;

    // ---- tokenise ----
    char *tok[4] = {nullptr, nullptr, nullptr, nullptr};
    uint8_t ntok = 0;
    for (char *p = strtok(buf, " "); p && ntok < 4; p = strtok(nullptr, " "))
        tok[ntok++] = p;
    if (ntok == 0) return;

    VirtualDrone *f = &g_fleet[g_focus];

    // ---- fleet ... ----
    if (strcasecmp(tok[0], "fleet") == 0) {
        if (ntok == 1 || strcasecmp(tok[1], "list") == 0) { fleet_list(); return; }

        if (strcasecmp(tok[1], "set") == 0) {
            uint16_t slot, flight;
            if (ntok < 4 || !parse_u16(tok[2], &slot) || !parse_u16(tok[3], &flight)) {
                Serial.println("[Fleet] usage: fleet set <slot> <flight>");
                return;
            }
            if (slot >= g_n) {
                Serial.printf("[Fleet] slot %u not in the fleet (have 0..%u)\n",
                              slot, (unsigned)(g_n - 1));
                return;
            }
            if (!fleet_provision((uint8_t)slot, flight)) return;
            fleet_reg_refresh();          // that slot's leaf BE must be re-issued
            fleet_restagger(millis());
            if (rid_transport_active() == RID_RADIO_BT) fleet_bt_reset(millis());
            Serial.printf("[Fleet] slot %u -> flight %u (%s)\n",
                          slot, flight, drone_playback_name(flight));
            fleet_list();
            return;
        }

        uint16_t cnt;
        if (!parse_u16(tok[1], &cnt)) {
            Serial.println("[Fleet] usage: fleet <1..3> | fleet <n> same <flight> | "
                           "fleet set <slot> <flight> | fleet list");
            return;
        }
        if (ntok >= 4 && strcasecmp(tok[2], "same") == 0) {
            uint16_t fl;
            if (!parse_u16(tok[3], &fl)) { Serial.println("[Fleet] bad flight index"); return; }
            fleet_set_size((uint8_t)cnt, true, fl);
        } else {
            fleet_set_size((uint8_t)cnt, false, 0);
        }
        return;
    }

    // ---- time [<unix>] : the board's clock (session 3) ----
    // <unix> = whole seconds since 1970-01-01T00:00:00Z, UTC by definition.
    if (strcasecmp(tok[0], "time") == 0) {
        if (ntok == 1) { fleet_print_time(); return; }
        char *end = nullptr;
        unsigned long long v = strtoull(tok[1], &end, 10);
        if (end == tok[1] || *end != '\0' || v > 0xFFFFFFFFULL ||
            !drip_time_set_unix((uint32_t)v)) {
            Serial.println("[Time] usage: time <unix>   whole seconds since "
                           "1970-01-01T00:00:00Z (UTC), 2024 or later, "
                           "e.g. time 1790800260");
            return;
        }
        fleet_print_time();
        // Endorsements already signed carry the OLD date and would stay
        // outside their validity window (RFC 9575 §3.2.4.3). Re-sign them now,
        // exactly as a fleet change does. Packs, Wrappers, Manifests and the
        // Location/System timestamps pick up the new time at their next build.
        fleet_reg_refresh();
        if (rid_transport_active() == RID_RADIO_BT) fleet_bt_reset(millis());  // rebuild Link pages
        Serial.println("[Time] endorsement chain re-signed with the new time. Endorsements "
                       "sent BEFORE this point keep the old date (E-LINK-04 in a capture).");
        return;
    }

    // ---- identity [<0..5>] : which test identity the focused slot broadcasts ----
    // Session 3 (2026-09-30). Identities 3-5 are deliberately faulty or unusual
    // test identities (det_generator.h): 3 malformed DET, 4 chain C (air-only),
    // 5 bad endorsement signature.
    if (strcasecmp(tok[0], "identity") == 0) {
        static const char *const NOTE[DET_IDENTITY_COUNT] = {
            "valid, chain A", "valid, chain A", "valid, chain A",
            "MALFORMED DET: hash does not match the key (expect E-LINK-01)",
            "valid, CHAIN C: only the Apex anchors it (air-only)",
            "BAD ENDORSEMENT SIGNATURE (expect E-LINK-02)" };
        if (ntok == 1) {
            Serial.printf("[Identity] slot %u broadcasts identity %u - %s\n",
                          (unsigned)g_focus, (unsigned)f->id.index, NOTE[f->id.index]);
            for (uint8_t i = 0; i < DET_IDENTITY_COUNT; i++)
                Serial.printf("[Identity]   %u : %s\n", (unsigned)i, NOTE[i]);
            return;
        }
        uint16_t v;
        if (!parse_u16(tok[1], &v) || v >= DET_IDENTITY_COUNT) {
            Serial.printf("[Identity] usage: identity <0..%u>   (acts on the focused slot, "
                          "now %u)\n", (unsigned)(DET_IDENTITY_COUNT - 1), (unsigned)g_focus);
            return;
        }
        // Two slots broadcasting one DET would look like an impersonation
        // (experiment E3 exists for that, as a separate build). Refuse.
        for (uint8_t s = 0; s < g_n; s++) {
            if (s != g_focus && g_fleet[s].active && g_fleet[s].id.index == v) {
                Serial.printf("[Identity] refused: slot %u already broadcasts identity %u\n",
                              (unsigned)s, (unsigned)v);
                return;
            }
        }
        // A new identity is a new UA: provision the slot again (fresh Manifest
        // ledger, counters), keeping its flight, then re-sign the chain so the
        // slot's endorsement and its chain's upper links are the right ones.
        const uint16_t flight = f->track.flight;
        const uint8_t  old    = g_slot_ident[g_focus];
        g_slot_ident[g_focus] = (uint8_t)v;
        if (!fleet_provision(g_focus, flight)) {
            g_slot_ident[g_focus] = old;
            fleet_provision(g_focus, flight);
            return;
        }
        fleet_reg_refresh();
        fleet_restagger(millis());
        if (rid_transport_active() == RID_RADIO_BT) fleet_bt_reset(millis());
        Serial.printf("[Identity] slot %u now broadcasts identity %u - %s\n",
                      (unsigned)g_focus, (unsigned)v, NOTE[v]);
        det_print("[Identity]   DET = ", g_fleet[g_focus].id.det);
        return;
    }

    // ---- radio [status|wifi|bt] ----
    if (strcasecmp(tok[0], "radio") == 0) {
        if (ntok == 1 || strcasecmp(tok[1], "status") == 0) { fleet_radio_status(); return; }
        if (strcasecmp(tok[1], "wifi") == 0) {
            if (rid_transport_active() == RID_RADIO_WIFI) {
                Serial.println("[Radio] already on Wi-Fi.");
                return;
            }
            g_btq_n = g_btq_next = 0;             // drop any queued BT pages
            rid_transport_select(RID_RADIO_WIFI);
            fleet_restagger(millis());            // Wi-Fi packs resume at once
            return;
        }
        if (strcasecmp(tok[1], "bt") == 0) {
            if (rid_transport_active() == RID_RADIO_BT) {
                Serial.println("[Radio] already on Bluetooth.");
                return;
            }
            if (g_n > DRIP_BLE_FLEET_MAX) {
                Serial.printf("[Radio] refused: %u drones in the fleet, Bluetooth allows "
                              "%u (DRIP_BLE_FLEET_MAX). Run 'fleet %u' first.\n",
                              (unsigned)g_n, (unsigned)DRIP_BLE_FLEET_MAX,
                              (unsigned)DRIP_BLE_FLEET_MAX);
                return;
            }
            if (!rid_transport_select(RID_RADIO_BT)) return;   // failure printed
            fleet_bt_reset(millis());
            return;
        }
        // ---- radio slot <ms> : time each message stays on the air ----
        if (strcasecmp(tok[1], "slot") == 0) {
            uint16_t ms;
            if (ntok < 3 || !parse_u16(tok[2], &ms) || ms < 5 || ms > 1000) {
                Serial.println("[Radio] usage: radio slot <5..1000 ms>");
                return;
            }
            g_bt_slot_ms = ms;
            const float min_ms = ble_tx_interval() * 0.625f + 10.0f;   // interval + max advDelay
            Serial.printf("[Radio] BT slot = %u ms (%u messages/s)\n",
                          (unsigned)ms, (unsigned)(1000u / ms));
            if (ms < min_ms)
                Serial.printf("[Radio] WARNING: slot below interval + 10 ms advDelay "
                              "(%.1f ms): some messages may never be advertised.\n", min_ms);
            return;
        }
        // ---- radio int <units> : advertising interval, 0.625 ms units ----
        if (strcasecmp(tok[1], "int") == 0) {
            char *end = nullptr;
            long v = (ntok >= 3) ? strtol(tok[2], &end, 0) : -1;   // decimal or 0x..
            if (ntok < 3 || end == tok[2] || *end != '\0' ||
                !ble_tx_set_interval((uint16_t)((v < 0 || v > 0xFFFF) ? 0 : v))) {
                Serial.println("[Radio] usage: radio int <0x20..0x4000> (units of 0.625 ms)");
                return;
            }
            Serial.printf("[Radio] BT advertising interval = 0x%X (%.2f ms); "
                          "applied at the next advertising start\n",
                          (unsigned)v, v * 0.625f);
            return;
        }
        Serial.println("[Radio] usage: radio | radio status | radio wifi | radio bt |");
        Serial.println("               radio slot <ms> | radio int <units>");
        return;
    }

    // ---- focus <slot> ----
    if (strcasecmp(tok[0], "focus") == 0) {
        uint16_t slot;
        if (ntok < 2 || !parse_u16(tok[1], &slot) || slot >= g_n) {
            Serial.printf("[Fleet] usage: focus <0..%u>\n", (unsigned)(g_n - 1));
            return;
        }
        g_focus = (uint8_t)slot;
        Serial.printf("[Fleet] focus = slot %u — list/info/next/reset/stop/<number> "
                      "now act on it\n", (unsigned)g_focus);
        return;
    }

    // ---- debug off|on|<slot> ----
    if (strcasecmp(tok[0], "debug") == 0) {
        if (ntok < 2) { Serial.println("[Fleet] usage: debug off|on|<slot>"); return; }
        if (strcasecmp(tok[1], "off") == 0) {
            g_debug_slot = -1;
            Serial.println("[Fleet] pack dump off");
        } else if (strcasecmp(tok[1], "on") == 0) {
            g_debug_slot = (int8_t)g_focus;
            Serial.printf("[Fleet] pack dump -> slot %u (focused)\n", (unsigned)g_focus);
        } else {
            uint16_t slot;
            if (!parse_u16(tok[1], &slot) || slot >= g_n) {
                Serial.printf("[Fleet] usage: debug off|on|<0..%u>\n", (unsigned)(g_n - 1));
                return;
            }
            g_debug_slot = (int8_t)slot;
            Serial.printf("[Fleet] pack dump -> slot %u ONLY (one drone is all the "
                          "115200 link can carry)\n", slot);
        }
        return;
    }

    // ---- legacy single-drone commands: act on the FOCUSED slot ----
    if (strcasecmp(tok[0], "list") == 0) { drone_playback_list(); fleet_list(); return; }

    if (strcasecmp(tok[0], "info") == 0) {
        Serial.printf("[Playback] drone %u: identity %u, flight %u (%s), point %u/%u%s\n",
                      (unsigned)g_focus, (unsigned)f->id.index, f->track.flight,
                      drone_playback_name(f->track.flight),
                      f->track.idx, drone_playback_points(f->track.flight),
                      f->track.finished
                        ? (f->track.stopped_by_user ? "  [stopped by command]"
                                                    : "  [finished — holding]")
                        : "");
        return;
    }

    if (strcasecmp(tok[0], "stop") == 0) { drone_playback_stop(&f->track, g_focus); return; }

    if (strcasecmp(tok[0], "reset") == 0) {
        drone_playback_reset(&f->track);
        f->off_air = false;
        Serial.printf("[Playback] drone %u restarted at point 0\n", (unsigned)g_focus);
        return;
    }

    if (strcasecmp(tok[0], "next") == 0) {
        DronePosition p = drone_playback_next(&f->track, 0, g_focus);
        Serial.printf("[Playback] drone %u -> lat=%.7f lon=%.7f alt=%.1f m "
                      "spd=%.1f hdg=%.0f ts=%lu\n",
                      (unsigned)g_focus, p.lat, p.lon, p.alt_m,
                      p.speed_mps, p.heading_deg, (unsigned long)p.unix_time_s);
        return;
    }

    // ---- <number> : select a flight for the focused slot ----
    uint16_t v;
    if (parse_u16(tok[0], &v)) {
        if (!drone_playback_select(&f->track, v)) {
            Serial.printf("[Playback] invalid index %u (0..%u)\n",
                          v, drone_playback_count() - 1);
            return;
        }
        f->off_air = false;
        Serial.printf("[Playback] drone %u selected flight %u: %s (%u points, ~%.1f min)\n",
                      (unsigned)g_focus, v, drone_playback_name(v),
                      drone_playback_points(v), drone_playback_duration_s(v) / 60.0f);
        return;
    }

    Serial.printf("[Fleet] unknown command '%s'\n", tok[0]);
    Serial.println("        fleet <1..3> | fleet <n> same <flight> | fleet set <slot> <flight> |");
    Serial.println("        fleet list | focus <slot> | debug off|on|<slot> |");
    Serial.println("        list | info | next | reset | stop | <number> |");
    Serial.println("        time | time <unix> | identity | identity <0..5> |");
    Serial.println("        radio | radio status | radio wifi | radio bt |");
    Serial.println("        radio slot <ms> | radio int <units>");
}
