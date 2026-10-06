#include "ble_tx.h"
#include "ble_frame.h"
#include "drip_config.h"
#include <Arduino.h>
#include <string.h>

// Keep the BT controller memory (see the root-cause note in ble_tx.h).
// The header only exists from arduino-esp32 3.3.7; older cores keep the memory
// by default, so nothing is needed there.
#if __has_include("esp32-hal-bt-mem.h")
#include "esp32-hal-bt-mem.h"
#endif

extern "C" {
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_err.h"
}

// ---------------------------------------------------------------------------
// Per-slot static random addresses, MSB first (esp_bd_addr_t order).
// ---------------------------------------------------------------------------
static const uint8_t SLOT_BLE_ADDR[DET_IDENTITY_SLOTS][6] = {
    { 0xC2, 0x44, 0x52, 0x49, 0x50, 0x00 },   // drone 0
    { 0xC2, 0x44, 0x52, 0x49, 0x50, 0x01 },   // drone 1
    { 0xC2, 0x44, 0x52, 0x49, 0x50, 0x02 },   // drone 2
};

// ---------------------------------------------------------------------------
// State. The GAP callback runs in the Bluedroid (BTC) task, so every field it
// writes is volatile and only ever written there or before a request is made.
// ---------------------------------------------------------------------------
static bool              s_init_done  = false;   // ble_tx_init() already ran
static bool              s_ready      = false;   // ...and succeeded
static volatile bool     s_busy       = false;   // waiting for a GAP completion
static volatile bool     s_advertising= false;   // controller is advertising
static uint32_t          s_errors     = 0;       // stats only; see err_inc()
static uint32_t          s_puts       = 0;
static int               s_addr_slot  = -1;      // slot whose address is set
static bool              s_start_pending = false;// start after data-set completes
static uint32_t          s_switches   = 0;       // stops made to change address
static uint16_t          s_interval   = DRIP_BLE_ADV_INT_UNITS;  // runtime value

static esp_ble_adv_params_t s_adv_params;

// Written from both the Arduino loop and the Bluedroid task: atomic increment.
static inline void err_inc() { __atomic_fetch_add(&s_errors, 1, __ATOMIC_RELAXED); }

// Pending start sequence for a new slot: set address -> set data -> start.
static uint8_t s_pending_adv[ODID_BT_LEGACY_ADV_BYTES];

static void report(const char *step, esp_err_t e) {
    Serial.printf("[BLE] %-34s %s (0x%X)\n", step, esp_err_to_name(e), (unsigned)e);
}

// ---------------------------------------------------------------------------
// GAP event callback (Bluedroid task). Kept short: flags only, plus the next
// request of a start sequence. Serial output here is limited to errors, which
// are rare; routine events print nothing.
// ---------------------------------------------------------------------------
static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    switch (event) {
    case ESP_GAP_BLE_SET_STATIC_RAND_ADDR_EVT:
        if (param->set_rand_addr_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            err_inc();
            Serial.printf("[BLE] set random address failed, status %d\n",
                          (int)param->set_rand_addr_cmpl.status);
            s_busy = false;
            return;
        }
        // Address in place: now the advertising data.
        if (esp_ble_gap_config_adv_data_raw(s_pending_adv, ODID_BT_LEGACY_ADV_BYTES) != ESP_OK) {
            err_inc(); s_busy = false;
        }
        break;

    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
        if (param->adv_data_raw_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            err_inc();
            Serial.printf("[BLE] set advertising data failed, status %d\n",
                          (int)param->adv_data_raw_cmpl.status);
            s_busy = false;
            return;
        }
        if (s_start_pending) {
            s_start_pending = false;
            if (esp_ble_gap_start_advertising(&s_adv_params) != ESP_OK) {
                err_inc(); s_busy = false;
            }
            // s_busy cleared by ADV_START_COMPLETE
        } else {
            s_busy = false;       // data replaced while advertising: done
        }
        break;

    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
        if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
            err_inc();
            // Most likely cause on a BT 4.2 controller: the advertising
            // interval is below what it accepts for ADV_NONCONN_IND.
            Serial.printf("[BLE] start advertising failed, status %d "
                          "(interval 0x%X: try 'radio int <units>')\n",
                          (int)param->adv_start_cmpl.status,
                          (unsigned)s_interval);
            s_advertising = false;
        } else {
            s_advertising = true;
        }
        s_busy = false;
        break;

    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
        s_advertising = false;
        s_busy = false;
        break;

    default:
        break;
    }
}

// ---------------------------------------------------------------------------
bool ble_tx_init() {
    if (s_init_done) return s_ready;
    s_init_done = true;

    Serial.printf("[BLE] init: free heap before = %u bytes\n", (unsigned)ESP.getFreeHeap());
    esp_err_t e;

    // Classic BT is never used: give its memory back before the controller
    // starts (esp_bt.h). Harmless if it was already released.
    e = esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);
    report("mem_release(CLASSIC_BT)", e);

    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_IDLE) {
        esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        cfg.mode = ESP_BT_MODE_BLE;   // must equal the mode passed to enable()
        e = esp_bt_controller_init(&cfg);
        report("esp_bt_controller_init(BLE)", e);
        if (e != ESP_OK) return false;
    }
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_INITED) {
        e = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        report("esp_bt_controller_enable(BLE)", e);
        if (e != ESP_OK) return false;
    }
    if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_UNINITIALIZED) {
        e = esp_bluedroid_init();
        report("esp_bluedroid_init", e);
        if (e != ESP_OK) return false;
    }
    if (esp_bluedroid_get_status() == ESP_BLUEDROID_STATUS_INITIALIZED) {
        e = esp_bluedroid_enable();
        report("esp_bluedroid_enable", e);
        if (e != ESP_OK) return false;
    }
    e = esp_ble_gap_register_callback(gap_cb);
    report("esp_ble_gap_register_callback", e);
    if (e != ESP_OK) return false;

    // ASTM §5.4.6.3 (BB40010): connectionless broadcast, un-coded (LE 1M).
    memset(&s_adv_params, 0, sizeof(s_adv_params));
    s_adv_params.adv_int_min       = s_interval;
    s_adv_params.adv_int_max       = s_interval;
    s_adv_params.adv_type          = ADV_TYPE_NONCONN_IND;    // Table 14 PDU Type 0x2
    s_adv_params.own_addr_type     = BLE_ADDR_TYPE_RANDOM;    // Table 14 TxAdd = 1
    s_adv_params.channel_map       = ADV_CHNL_ALL;            // 37, 38, 39 (§5.4.6.2)
    s_adv_params.adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY;

    s_ready = true;
    Serial.printf("[BLE] ready: Legacy ADV_NONCONN_IND, interval 0x%X (%.2f ms), "
                  "slot %u ms; free heap after = %u bytes\n",
                  (unsigned)s_interval, s_interval * 0.625f,
                  (unsigned)DRIP_BLE_ADV_SLOT_MS, (unsigned)ESP.getFreeHeap());
    return true;
}

bool ble_tx_ready() { return s_ready; }
bool ble_tx_busy()  { return s_busy; }

// ---------------------------------------------------------------------------
BlePut ble_tx_put(uint8_t slot, const uint8_t msg[F3411_MSG_BYTES], uint8_t counter) {
    if (!s_ready || s_busy || slot >= DET_IDENTITY_SLOTS) return BLE_PUT_BUSY;

    uint8_t adv[ODID_BT_LEGACY_ADV_BYTES];
    ble_build_legacy_adv(msg, counter, adv);

    esp_err_t e;
    if (s_advertising && s_addr_slot == (int)slot) {
        // Same drone still on the air: replace the data only. The Link Layer
        // accepts a new advertising data set while advertising is enabled.
        s_busy = true;
        e = esp_ble_gap_config_adv_data_raw(adv, ODID_BT_LEGACY_ADV_BYTES);
        if (e != ESP_OK) { s_busy = false; err_inc(); report("config_adv_data_raw", e); return BLE_PUT_ERROR; }
        s_puts++;
        return BLE_PUT_OK;
    }

    if (s_advertising) {
        // A different slot's address is needed, and the random address cannot
        // change while advertising (Bluetooth Core, HCI LE Set Random Address).
        // Stop first; the caller retries once ble_tx_busy() clears.
        s_busy = true;
        e = esp_ble_gap_stop_advertising();
        if (e != ESP_OK) { s_busy = false; err_inc(); report("stop_advertising", e); return BLE_PUT_ERROR; }
        s_switches++;
        return BLE_PUT_SWITCHING;
    }

    // Not advertising: address -> data -> start, chained through gap_cb.
    memcpy(s_pending_adv, adv, sizeof(adv));
    s_adv_params.adv_int_min = s_interval;     // picks up a runtime change
    s_adv_params.adv_int_max = s_interval;
    s_start_pending = true;
    s_busy = true;
    if (s_addr_slot != (int)slot) {
        uint8_t a[6];
        memcpy(a, SLOT_BLE_ADDR[slot], 6);
        e = esp_ble_gap_set_rand_addr(a);
        if (e != ESP_OK) { s_busy = false; s_start_pending = false; err_inc();
                           report("set_rand_addr", e); return BLE_PUT_ERROR; }
        s_addr_slot = slot;
    } else {
        e = esp_ble_gap_config_adv_data_raw(s_pending_adv, ODID_BT_LEGACY_ADV_BYTES);
        if (e != ESP_OK) { s_busy = false; s_start_pending = false; err_inc();
                           report("config_adv_data_raw", e); return BLE_PUT_ERROR; }
    }
    s_puts++;
    return BLE_PUT_OK;
}

// ---------------------------------------------------------------------------
// Stop and wait (up to 200 ms each way) for the controller to confirm.
static bool stop_and_wait() {
    if (!s_ready || !s_advertising) return false;
    uint32_t t0 = millis();
    while (s_busy && (millis() - t0) < 200) delay(1);   // let a pending request finish
    if (!s_advertising) return false;
    s_busy = true;
    esp_err_t e = esp_ble_gap_stop_advertising();
    if (e != ESP_OK) { s_busy = false; err_inc(); report("stop_advertising", e); return false; }
    t0 = millis();
    while (s_busy && (millis() - t0) < 200) delay(1);
    return true;
}

void ble_tx_stop() {
    if (stop_and_wait())
        Serial.println("[BLE] advertising stopped - no Remote ID on Bluetooth.");
}

void ble_tx_stop_slot(uint8_t slot) {
    if (s_addr_slot != (int)slot) return;          // another drone is on the air
    if (stop_and_wait())
        Serial.printf("[BLE] slot %u off the air.\n", (unsigned)slot);
}

bool ble_tx_set_interval(uint16_t units) {
    if (units < 0x0020 || units > 0x4000) return false;   // HCI LE Set Advertising Parameters range
    s_interval = units;
    if (s_ready) stop_and_wait();                  // the next put restarts with the new value
    return true;
}

uint16_t ble_tx_interval() { return s_interval; }

const uint8_t *ble_tx_addr(uint8_t slot) {
    if (slot >= DET_IDENTITY_SLOTS) return SLOT_BLE_ADDR[0];
    return SLOT_BLE_ADDR[slot];
}

uint32_t ble_tx_puts()   { return s_puts; }
uint32_t ble_tx_errors() { return s_errors; }
uint32_t ble_tx_switches() { return s_switches; }
