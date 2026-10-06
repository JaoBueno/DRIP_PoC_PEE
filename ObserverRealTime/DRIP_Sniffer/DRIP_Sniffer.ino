// =============================================================================
//  DRIP_Sniffer — ESP32 #2 : over-the-air capture of ASTM F3411-22a Broadcast RID
//
// -----------------------------------------------------------------------------
//  SESSION 3 (2026-09-29): Wi-Fi OR Bluetooth Legacy, chosen at runtime.
//
//  Serial commands (typed at SNIFFER_BAUD, or sent by
//  `arduino_logger.py --cmd "radio bt"`):
//      radio | radio status   which radio is listening, plus the counters
//      radio wifi             ASTM F3411-22a §5.4.9 Wi-Fi Beacon, channel 6.
//                             The boot default. Output below is UNCHANGED.
//      radio bt               ASTM F3411-22a §5.4.6 Bluetooth Legacy
//                             advertising, passive scan. "Format BT" output.
//
//  FORMAT BT — one advert = one '#B' metadata line + one hex line:
//      #B addr=C2:44:52:49:50:00 rssi=-42 t_ms=12345 len=29 t_us=12345678 atype=1
//      FA FF 0D 07 02 12 ...
//    * The first four fields and the hex line follow the MOCK_DET_DRIP fork's
//      Format BT, so its odid.parse_format_bt() reads these captures. t_us and
//      atype are APPENDED after len, where that parser's regex ignores them.
//    * hex = the Service Data AD field from the UUID on: [FA FF][0D][counter]
//      [25-octet ASTM message] = 29 octets for Legacy (ASTM Table 14).
//    * t_us = esp_timer microseconds since boot, taken when Bluedroid delivers
//      the report to the application. It includes a few ms of host-stack
//      jitter: good for medians and gaps, not radio-level timing.
//    * atype = the advertiser address type (0 public, 1 random). The DRIP
//      transmitter uses static random addresses, so 1 is expected.
//    * EVERY received copy is logged (duplicate filter OFF): the copies are
//      what bt_timing.py uses to measure the real advertising interval.
//
//  BUILD: Tools > Partition Scheme > "Huge APP (3MB No OTA/1MB SPIFFS)". The
//  Wi-Fi driver plus Bluedroid do not fit the default partition.
//
//  STAGE 1 of the observer redesign. This board does NOT transmit. It listens on
//  channel 6 in promiscuous mode, keeps only 802.11 Beacons carrying an Open
//  Drone ID vendor IE, and prints them over serial in a hex format that
//  Wireshark can import directly.
//
// -----------------------------------------------------------------------------
//  WHY THIS EXISTS
//
//  The serial debug path (Format L) on the TRANSMITTER prints the pack it
//  *intended* to send — read out of RAM, before esp_wifi_80211_tx() is even
//  called. It would report a flawless dump if the frame never left the antenna,
//  if the MAC header were malformed, or if the driver rewrote the source
//  address. Since the whole transmission layer was recently replaced with
//  hand-built frames, the one thing most in need of verification is precisely
//  the thing Format L structurally cannot see.
//
//  This sniffer reads the AIR. What it prints actually propagated.
//
//  It also recovers the source MAC, which the Python observer currently
//  discards (it starts parsing at offset 36 and never reads Addr2). That
//  blindness is not cosmetic: it is why a single-BSSID transmitter design would
//  have looked healthy to our own tooling while a real receiver saw one
//  flickering aircraft.
//
// -----------------------------------------------------------------------------
//  WHY A SECOND ESP32 RATHER THAN A MONITOR-MODE NIC
//
//  esp_wifi_set_promiscuous_rx_cb() hands us wifi_promiscuous_pkt_t, whose
//  .payload begins at the 802.11 Frame Control field — with NO radiotap header.
//  That matters: a monitor-mode pcap prepends a variable-length radiotap header,
//  which would break odid.py's BEACON_TAGGED_START = 36 (and silently
//  mis-decode, which is worse than failing). Sniffing on an ESP32 sidesteps
//  radiotap entirely, needs no Npcap/monitor-mode support on the host, and
//  reuses the promiscuous RX path already proven by SPIKE_Beacon_Inject.
//
//  The RSSI / channel / timestamp that radiotap would have carried are
//  available here in rx_ctrl, and are emitted as '#' comments.
//
// -----------------------------------------------------------------------------
//  OUTPUT FORMAT — verified against text2pcap 4.2.2 + tshark before this
//  firmware was written (4 synthetic frames in -> 4 packets out, MACs, SSIDs,
//  OUI fa:0b:bc type 13 all dissected, timestamps preserved to microseconds).
//
//      # comment lines are ignored by text2pcap (verified)
//      HH:MM:SS.uuuuuu 000000 80 00 00 00 FF FF FF FF FF FF 02 44 52 49 50 00
//                      000010 02 44 52 49 50 00 00 00 00 00 00 00 00 00 00 00
//                      ...
//
//  The timestamp appears ONLY on a packet's first line; continuation lines are
//  padded to the same width (text2pcap ignores text before the offset).
//
//  IMPORT:
//      text2pcap -t "%H:%M:%S.%f" -l 105 capture.txt capture.pcap
//
//    -t "%H:%M:%S.%f"  the %f (fractional seconds) descriptor is REQUIRED.
//                      Older Wireshark docs show "%H:%M:%S." — on 4.2.2 that
//                      silently DROPS the fraction and every frame lands on the
//                      same timestamp. Verified the hard way.
//    -l 105            LINKTYPE_IEEE802_11 = raw 802.11, no radiotap.
//
//  With microsecond timestamps preserved, the capture can verify BOTH the
//  ~10 Hz per-drone beacon repeat and the 111 ms phase stagger between drones.
//
// -----------------------------------------------------------------------------
//  STANDARDS
//    ASTM F3411-22a §5.4.9.2 (BWFB0020) / Table 20 — the vendor IE we filter on:
//        Element ID 221 (0xDD) | Length | OUI FA-0B-BC | Vendor Type 0x0D
//    ASTM F3411-22a §5.4.9.1 (BWFB0010) — channel 6 as the single social channel
//    IEEE 802.11-2016 §9.3.3.3 — Beacon frame (type 0 management, subtype 8)
//
// -----------------------------------------------------------------------------
//  HOW TO RUN
//    1. Folder must be named exactly  DRIP_Sniffer/
//    2. Flash to the SECOND ESP32 (the transmitter keeps running its own build).
//    3. Serial Monitor at 921600 — see the BAUD note below.
//    4. Capture the text to a file, then run the text2pcap command above.
//       (Serial Monitor cannot save to a file; use a logger script, or
//        PuTTY/screen logging, or the Arduino IDE's Serial Monitor copy-paste.)
// =============================================================================

#include <Arduino.h>
#include <string.h>

// Keep the BT controller memory: arduino-esp32 >= 3.3.7 releases it at boot
// unless this header is included (see ble_tx.h in the transmitter).
#if __has_include("esp32-hal-bt-mem.h")
#include "esp32-hal-bt-mem.h"
#endif

extern "C" {
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
}

// -----------------------------------------------------------------------------
//  Configuration
// -----------------------------------------------------------------------------

// ASTM F3411-22a §5.4.9.1 (BWFB0010) — must match the transmitter's
// WIFI_CHANNEL_DRIP (beacon_tx_raw.h). This sniffer does NOT hop channels.
#define SNIFFER_CHANNEL     6

// Serial rate. Budget: a 296-byte frame emits ~624 chars (hex + offsets +
// metadata); 3 drones x 10 Hz = 30 frames/s = ~18.7 kB/s.
//   115200 -> 162% of the link  ** WILL DROP FRAMES **
//   460800 ->  41%              OK
//   921600 ->  20%              recommended
// If your USB-serial chip is unreliable at 921600 (CH340 often is above
// ~460800; CP2102 is usually fine), drop to 460800 here AND in the capture
// tool. Do NOT drop to 115200: the sniffer would silently lose frames and any
// rate analysis drawn from the capture would be wrong.
#define SNIFFER_BAUD        921600

// Ring buffer. The promiscuous callback MUST NOT print: it runs in the Wi-Fi
// driver task, and Serial.printf() blocks when the TX FIFO fills, which would
// stall the Wi-Fi stack and drop frames at the radio. So the callback only
// copies and returns; loop() does all the printing.
#define RING_SLOTS          16
#define MAX_FRAME           512   // our own frames are 296 B; headroom for others

// Offset of the first tagged parameter in a Beacon:
//   24 (MAC header) + 12 (timestamp/interval/capability). Same constant as
//   odid.py's BEACON_TAGGED_START — deliberately.
#define BEACON_TAGGED_START 36

// ASTM F3411-22a Table 20
static const uint8_t ODID_OUI[3] = { 0xFA, 0x0B, 0xBC };
#define ODID_VENDOR_TYPE    0x0D

// ASTM F3411-22a §5.4.6.4 Table 14 — Service Data, 16-bit UUID 0xFFFA, App Code 0x0D
#define BT_AD_TYPE_SVC16    0x16
#define BT_UUID_LO          0xFA
#define BT_UUID_HI          0xFF
#define BT_APP_CODE         0x0D

// Bluetooth passive scan. Window == interval means the receiver listens 100%
// of the time; the controller moves to the next advertising channel (37, 38,
// 39) at every interval. 0x50 = 50 ms (units of 0.625 ms). A bench choice,
// not an ASTM value: a 100% duty cycle catches the most advertising events,
// which is what the measurement needs.
#define BLE_SCAN_INTERVAL   0x50
#define BLE_SCAN_WINDOW     0x50

// Legacy advertising data is at most 31 octets; Bluedroid delivers AD + scan
// response in one 62-octet buffer.
#define BLE_ADV_MAX         62

// -----------------------------------------------------------------------------
//  State
// -----------------------------------------------------------------------------
struct Slot {
    uint8_t  buf[MAX_FRAME];
    uint16_t len;
    uint64_t t_us;
    int8_t   rssi;
    uint8_t  ch;
    // Bluetooth only (kind == 1)
    uint8_t  kind;          // 0 = Wi-Fi Beacon (Format A), 1 = BLE advert (Format BT)
    uint8_t  addr[6];       // advertiser address, most significant octet first
    uint8_t  atype;         // 0 public, 1 random
};

enum SnifRadio : uint8_t { SNIF_WIFI = 0, SNIF_BT = 1 };
static volatile SnifRadio g_radio = SNIF_WIFI;
static bool               g_bt_init_done = false;
static bool               g_bt_ready     = false;
static volatile bool      g_scan_param_ok  = false;
static volatile bool      g_scan_running   = false;
static volatile bool      g_scan_stop_done = false;
static volatile uint32_t  g_bt_seen_other  = 0;   // BLE adverts that were not ODID

static Slot              g_ring[RING_SLOTS];
static volatile uint16_t g_head = 0;      // written by the Wi-Fi task
static volatile uint16_t g_tail = 0;      // written by loop()
static volatile uint32_t g_captured = 0;
static volatile uint32_t g_dropped  = 0;  // ring overflow — serial too slow
static volatile uint32_t g_oversize = 0;  // frame > MAX_FRAME, skipped

// rx_ctrl.timestamp is a uint32 of MICROSECONDS -> it wraps every ~71.6 min.
// Recorded flight 26 alone runs 116.7 min, so a wrap WILL happen in a long
// capture and would make timestamps jump backwards. Extended to 64-bit here.
// Safe in the callback: single producer, frames arrive in order.
static uint32_t g_last_us   = 0;
static uint64_t g_wrap_base = 0;

// -----------------------------------------------------------------------------
//  Does this frame carry an Open Drone ID vendor IE?  (ASTM Table 20)
//
//  NOTE — we filter on the ODID OUI, NOT on our own MACs. Two reasons:
//    1. a real ODID drone nearby would also be captured (useful);
//    2. filtering by our MACs would HIDE the very defect this tool exists to
//       detect — a Remote ID payload arriving from an unexpected transmitter.
// -----------------------------------------------------------------------------
static bool has_odid_ie(const uint8_t *f, uint16_t len) {
    uint16_t pos = BEACON_TAGGED_START;
    while (pos + 2 <= len) {
        uint8_t id     = f[pos];
        uint8_t ie_len = f[pos + 1];
        if (pos + 2 + ie_len > len) return false;          // truncated/malformed
        if (id == 0xDD && ie_len >= 4 &&
            f[pos + 2] == ODID_OUI[0] &&
            f[pos + 3] == ODID_OUI[1] &&
            f[pos + 4] == ODID_OUI[2] &&
            f[pos + 5] == ODID_VENDOR_TYPE) {
            return true;
        }
        pos += 2 + ie_len;
    }
    return false;
}

// -----------------------------------------------------------------------------
//  Promiscuous RX callback — runs in the Wi-Fi driver task. KEEP IT SHORT.
//  No Serial, no malloc, no blocking.
// -----------------------------------------------------------------------------
static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = p->payload;

    // rx_ctrl.sig_len includes the 4-byte FCS, which the hardware appends and
    // which is not part of the frame we built. Strip it so the captured length
    // matches the transmitter exactly (a 9-message pack => 296 bytes) — that
    // equality is itself a useful check that nothing mangled the frame.
    int len = (int)p->rx_ctrl.sig_len - 4;
    if (len < BEACON_TAGGED_START) return;

    // Beacon only: Frame Control byte 0 = 0x80 (version 0, type 0 mgmt,
    // subtype 8). IEEE 802.11-2016 §9.3.3.3.
    if (f[0] != 0x80) return;

    if (!has_odid_ie(f, (uint16_t)len)) return;

    if (len > MAX_FRAME) { g_oversize++; return; }   // skip, never truncate:
                                                     // a truncated frame would
                                                     // decode as corrupt data
    // 64-bit extend the microsecond clock (see g_wrap_base).
    uint32_t t = p->rx_ctrl.timestamp;
    if (t < g_last_us) g_wrap_base += 0x100000000ULL;
    g_last_us = t;

    uint16_t next = (uint16_t)((g_head + 1) % RING_SLOTS);
    if (next == g_tail) { g_dropped++; return; }     // serial cannot keep up

    Slot *s = &g_ring[g_head];
    memcpy(s->buf, f, (size_t)len);
    s->len  = (uint16_t)len;
    s->t_us = g_wrap_base + t;
    s->rssi = p->rx_ctrl.rssi;
    s->ch   = p->rx_ctrl.channel;
    s->kind = 0;

    g_head = next;
    g_captured++;
}

// -----------------------------------------------------------------------------
//  Bluetooth: find the ODID Service Data AD structure in one advertising
//  report. Returns the offset of the UUID's first octet and its length
//  (UUID + App Code + counter + message), or -1.
//  ASTM F3411-22a Table 14: [len][0x16][FA FF][0D][counter][25 octets].
//  Filtering on UUID + App Code, not on our addresses, for the same two
//  reasons as has_odid_ie() above.
// -----------------------------------------------------------------------------
static int find_odid_svc(const uint8_t *ad, uint8_t ad_len, uint8_t *svc_len) {
    uint16_t pos = 0;
    while (pos + 1 < ad_len) {
        const uint8_t l = ad[pos];
        if (l == 0) break;                                   // early terminator
        if (pos + 1 + l > ad_len) return -1;                 // malformed
        const uint8_t t = ad[pos + 1];
        if (t == BT_AD_TYPE_SVC16 && l >= 4 &&
            ad[pos + 2] == BT_UUID_LO && ad[pos + 3] == BT_UUID_HI &&
            ad[pos + 4] == BT_APP_CODE) {
            *svc_len = (uint8_t)(l - 1);                     // octets after the type
            return pos + 2;
        }
        pos += 1 + l;
    }
    return -1;
}

// -----------------------------------------------------------------------------
//  Bluedroid GAP callback — runs in the Bluedroid (BTC) task. Same rule as
//  promisc_cb: copy into the ring and return, never print from here except for
//  the rare start-up status lines.
// -----------------------------------------------------------------------------
static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
    case ESP_GAP_BLE_SCAN_PARAM_SET_COMPLETE_EVT:
        g_scan_param_ok = (param->scan_param_cmpl.status == ESP_BT_STATUS_SUCCESS);
        break;
    case ESP_GAP_BLE_SCAN_START_COMPLETE_EVT:
        g_scan_running = (param->scan_start_cmpl.status == ESP_BT_STATUS_SUCCESS);
        break;
    case ESP_GAP_BLE_SCAN_STOP_COMPLETE_EVT:
        g_scan_running   = false;
        g_scan_stop_done = true;
        break;
    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
        const auto &r = param->scan_rst;
        if (r.search_evt != ESP_GAP_SEARCH_INQ_RES_EVT) break;
        if (g_radio != SNIF_BT) break;                       // late report after a switch
        uint8_t svc_len = 0;
        const uint8_t ad_len = (uint8_t)(r.adv_data_len + r.scan_rsp_len);
        int off = find_odid_svc(r.ble_adv, ad_len > BLE_ADV_MAX ? BLE_ADV_MAX : ad_len, &svc_len);
        if (off < 0) { g_bt_seen_other = g_bt_seen_other + 1; break; }

        const uint64_t t = (uint64_t)esp_timer_get_time();
        uint16_t next = (uint16_t)((g_head + 1) % RING_SLOTS);
        if (next == g_tail) { g_dropped = g_dropped + 1; break; }          // serial cannot keep up

        Slot *s = &g_ring[g_head];
        memcpy(s->buf, &r.ble_adv[off], svc_len);
        s->len   = svc_len;
        s->t_us  = t;
        s->rssi  = (int8_t)r.rssi;
        s->ch    = 0;                                        // not reported by Bluedroid
        s->kind  = 1;
        memcpy(s->addr, r.bda, 6);
        s->atype = (uint8_t)r.ble_addr_type;
        g_head = next;
        g_captured = g_captured + 1;
        break;
    }
    default:
        break;
    }
}

// -----------------------------------------------------------------------------
//  Emit one frame in text2pcap hexdump format.
//
//  "HH:MM:SS.uuuuuu " is exactly 16 characters, so continuation lines are
//  padded with 16 spaces to keep the offsets aligned. text2pcap ignores text
//  before the offset; the timestamp is parsed only where a packet starts.
// -----------------------------------------------------------------------------
static void emit(const Slot *s) {
    uint32_t secs = (uint32_t)(s->t_us / 1000000ULL);
    uint32_t frac = (uint32_t)(s->t_us % 1000000ULL);
    unsigned hh = (secs / 3600) % 24;
    unsigned mm = (secs / 60) % 60;
    unsigned ss = secs % 60;

    // '#' lines are ignored by text2pcap (verified) — metadata for humans and
    // for a future observer parser reading this text directly.
    Serial.printf("#F rssi=%d ch=%u len=%u\n", (int)s->rssi, (unsigned)s->ch,
                  (unsigned)s->len);

    for (uint16_t off = 0; off < s->len; off += 16) {
        if (off == 0) Serial.printf("%02u:%02u:%02u.%06u ", hh, mm, ss,
                                    (unsigned)frac);
        else          Serial.print("                ");     // 16 spaces
        Serial.printf("%06X", (unsigned)off);
        for (uint16_t k = off; k < off + 16 && k < s->len; k++)
            Serial.printf(" %02X", s->buf[k]);
        Serial.println();
    }
}

// -----------------------------------------------------------------------------
//  Emit one BLE advert in Format BT (see the header).
// -----------------------------------------------------------------------------
static void emit_bt(const Slot *s) {
    Serial.printf("#B addr=%02X:%02X:%02X:%02X:%02X:%02X rssi=%d t_ms=%lu len=%u "
                  "t_us=%llu atype=%u\n",
                  s->addr[0], s->addr[1], s->addr[2], s->addr[3], s->addr[4], s->addr[5],
                  (int)s->rssi, (unsigned long)(s->t_us / 1000ULL), (unsigned)s->len,
                  (unsigned long long)s->t_us, (unsigned)s->atype);
    for (uint16_t k = 0; k < s->len; k++) {
        Serial.printf("%02X", s->buf[k]);
        if (k + 1 < s->len) Serial.print(' ');
    }
    Serial.println();
}

// -----------------------------------------------------------------------------
//  Bluetooth bring-up — only on the first `radio bt`, so a BT failure never
//  stops the Wi-Fi sniffer from booting. Every step is reported as a '#'
//  comment, which every capture parser ignores.
// -----------------------------------------------------------------------------
static bool bt_step(const char *what, esp_err_t e) {
    Serial.printf("# BT %-30s %s\n", what, esp_err_to_name(e));
    return e == ESP_OK;
}

static bool bt_init() {
    if (g_bt_init_done) return g_bt_ready;
    g_bt_init_done = true;

    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);   // BLE only
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE) {
        esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        cfg.mode = ESP_BT_MODE_BLE;
        if (!bt_step("esp_bt_controller_init(BLE)", esp_bt_controller_init(&cfg))) return false;
    }
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_INITED)
        if (!bt_step("esp_bt_controller_enable(BLE)", esp_bt_controller_enable(ESP_BT_MODE_BLE))) return false;
    if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_UNINITIALIZED)
        if (!bt_step("esp_bluedroid_init", esp_bluedroid_init())) return false;
    if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_INITIALIZED)
        if (!bt_step("esp_bluedroid_enable", esp_bluedroid_enable())) return false;
    if (!bt_step("esp_ble_gap_register_callback", esp_ble_gap_register_callback(gap_cb))) return false;

    esp_ble_scan_params_t sp = {};
    sp.scan_type          = BLE_SCAN_TYPE_PASSIVE;           // listen only, never transmit
    sp.own_addr_type      = BLE_ADDR_TYPE_PUBLIC;
    sp.scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL;
    sp.scan_interval      = BLE_SCAN_INTERVAL;
    sp.scan_window        = BLE_SCAN_WINDOW;
    sp.scan_duplicate     = BLE_SCAN_DUPLICATE_DISABLE;      // log EVERY copy
    g_scan_param_ok = false;
    if (!bt_step("esp_ble_gap_set_scan_params", esp_ble_gap_set_scan_params(&sp))) return false;
    uint32_t t0 = millis();
    while (!g_scan_param_ok && millis() - t0 < 500) delay(1);
    if (!g_scan_param_ok) { Serial.println("# BT scan parameters rejected"); return false; }

    g_bt_ready = true;
    return true;
}

// -----------------------------------------------------------------------------
//  Radio switch. Only one radio listens at a time, so the ring buffer always
//  has one producer.
// -----------------------------------------------------------------------------
static void wifi_listen(bool on) {
    if (on) {
        esp_wifi_start();
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE);
    } else {
        esp_wifi_set_promiscuous(false);
        esp_wifi_stop();
    }
}

static void radio_select(SnifRadio r) {
    if (r == g_radio) {
        Serial.printf("# radio already %s\n", r == SNIF_BT ? "bt" : "wifi");
        return;
    }
    if (r == SNIF_BT) {
        if (!bt_init()) {                                    // Wi-Fi keeps listening
            Serial.println("# radio bt FAILED - still listening on Wi-Fi");
            return;
        }
        wifi_listen(false);
        g_radio = SNIF_BT;
        esp_err_t e = esp_ble_gap_start_scanning(0);         // 0 = until stopped
        Serial.printf("# radio=bt  ASTM F3411-22a 5.4.6 Legacy, passive scan "
                      "interval=window=%.1f ms, duplicates kept (%s)\n",
                      BLE_SCAN_INTERVAL * 0.625f, esp_err_to_name(e));
        Serial.println("# Format BT: '#B addr=.. rssi=.. t_ms=.. len=.. t_us=.. atype=..' then the Service Data hex (UUID first)");
    } else {
        g_radio = SNIF_WIFI;                                 // late BLE reports now ignored
        g_scan_stop_done = false;
        esp_ble_gap_stop_scanning();
        uint32_t t0 = millis();
        while (!g_scan_stop_done && millis() - t0 < 300) delay(1);
        wifi_listen(true);
        Serial.printf("# radio=wifi  channel=%d  Format A (unchanged)\n", SNIFFER_CHANNEL);
    }
}

static void radio_status() {
    Serial.printf("# radio=%s captured=%u dropped=%u oversize=%u bt_non_odid=%u\n",
                  g_radio == SNIF_BT ? "bt" : "wifi",
                  (unsigned)g_captured, (unsigned)g_dropped, (unsigned)g_oversize,
                  (unsigned)g_bt_seen_other);
}

// -----------------------------------------------------------------------------
//  Serial commands, read without blocking the drain loop.
// -----------------------------------------------------------------------------
static void poll_cmd() {
    static char    line[32];
    static uint8_t n = 0;
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\r') continue;
        if (c != '\n') { if (n < sizeof(line) - 1) line[n++] = c; continue; }
        line[n] = '\0'; n = 0;
        if      (strcasecmp(line, "radio bt")   == 0) radio_select(SNIF_BT);
        else if (strcasecmp(line, "radio wifi") == 0) radio_select(SNIF_WIFI);
        else if (strcasecmp(line, "radio") == 0 || strcasecmp(line, "radio status") == 0)
            radio_status();
        else if (line[0] != '\0')
            Serial.println("# commands: radio | radio status | radio wifi | radio bt");
    }
}

// -----------------------------------------------------------------------------
void setup() {
    Serial.begin(SNIFFER_BAUD);
    delay(600);

    esp_err_t nvs = nvs_flash_init();
    if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    // STA, never connected — same posture as the transmitter. Nothing is
    // associated, nothing beacons, and the radio stays parked on our channel.
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Management frames only: beacons are mgmt subtype 8. Filtering here rather
    // than in the callback keeps the driver from waking us for every data frame
    // on a busy 2.4 GHz band.
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filt));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&promisc_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(SNIFFER_CHANNEL, WIFI_SECOND_CHAN_NONE));

    // The file documents its own import command — so a capture handed to
    // another engineer is self-describing.
    Serial.println();
    Serial.println("# DRIP-SNIFFER v1 — over-the-air ASTM F3411-22a Broadcast RID capture");
    Serial.printf ("# channel=%d  baud=%d  filter=Beacon + vendor IE OUI FA-0B-BC type 0x0D\n",
                   SNIFFER_CHANNEL, SNIFFER_BAUD);
    Serial.println("# FCS stripped; frame starts at 802.11 Frame Control (no radiotap).");
    Serial.println("# import:  text2pcap -t \"%H:%M:%S.%f\" -l 105 capture.txt capture.pcap");
    Serial.println("# NOTE: the %f is required; \"%H:%M:%S.\" silently drops the fraction.");
    Serial.println("# timestamps are microseconds since THIS board booted, not wall clock.");
    Serial.println("# commands: radio | radio status | radio wifi | radio bt  (boots on wifi)");
    Serial.println("#");
}

// -----------------------------------------------------------------------------
void loop() {
    // Drain the ring. Printing happens only here, never in the callback.
    while (g_tail != g_head) {
        const Slot *s = &g_ring[g_tail];
        if (s->kind == 1) emit_bt(s); else emit(s);
        g_tail = (uint16_t)((g_tail + 1) % RING_SLOTS);
    }

    poll_cmd();   // between records, so a command's reply never splits a hexdump

    // Periodic health line. Emitted only between packets (the ring is drained
    // first), so it can never split a hexdump.
    //
    // g_dropped > 0 means the ring overflowed: the serial link could not keep
    // up and frames were LOST. Any rate/interval analysis from such a capture
    // is unsound — raise the baud or reduce the fleet before trusting it.
    static uint32_t last = 0;
    if (millis() - last >= 10000) {
        last = millis();
        // radio= is APPENDED so live_feed.py's existing regex still matches.
        Serial.printf("# stats captured=%u dropped=%u oversize=%u  (dropped>0 => "
                      "capture is INCOMPLETE) radio=%s\n",
                      (unsigned)g_captured, (unsigned)g_dropped,
                      (unsigned)g_oversize, g_radio == SNIF_BT ? "bt" : "wifi");
    }
}
