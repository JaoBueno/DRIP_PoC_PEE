#pragma once
#include <stdint.h>
#include "f3411_messages.h"   // F3411_MSG_BYTES
#include "det_generator.h"    // DET_IDENTITY_SLOTS

// ---------------------------------------------------------------------------
// Bluetooth LEGACY advertising backend — ASTM F3411-22a §5.4.6
//
// Radio layer only. It puts ONE 25-octet ASTM message on the air as an
// ADV_NONCONN_IND (BB40010, uncoded LE 1M) framed per Table 14 (BB40030, via
// ble_frame.*). The controller repeats that advertisement every
// DRIP_BLE_ADV_INT_UNITS until the next ble_tx_put() replaces the data.
// Choosing WHICH message goes out and WHEN is the fleet scheduler's job
// (drone_fleet.cpp, RFC 9575 §6.4 schedule).
//
// STACK: Bluedroid, through the ESP-IDF GAP API. It is the stack the installed
// Arduino core is built with (BT_Capability_Check: "BT host stack: Bluedroid"),
// so no external library is needed. Only the BLE 4.2 legacy GAP calls are used.
//
// WHY btStartMode() FAILED IN BT_Capability_Check (root cause, from the core
// source, arduino-esp32 3.3.7/3.3.8 cores/esp32/esp32-hal-misc.c):
//   initArduino() calls esp_bt_controller_mem_release(ESP_BT_MODE_BTDM) at
//   boot unless btInUse() is true, and btInUse() is true only when a sketch
//   includes esp32-hal-bt-mem.h (as the core's BT libraries do). The diagnostic
//   did not, so the controller memory was gone before setup() and
//   esp_bt_controller_init() could never succeed. ble_tx.cpp includes that
//   header, which keeps the memory. Cores <= 3.3.6 keep it by default.
//
// ADDRESSES: one STATIC RANDOM address per slot, C2:44:52:49:50:0N. The two
// most significant bits = 0b11 mark it static random (Bluetooth Core 5.0
// Vol 6 Part B §1.3.2.1); Table 14 TxAdd = 1 ("Random Address"). The last five
// octets mirror the Wi-Fi slot MACs 02:44:52:49:50:0N so a log reads the same.
// ---------------------------------------------------------------------------

// Bring up the BT controller (BLE mode) and Bluedroid. Idempotent: the first
// call does the work and prints every step with its esp_err_t name and the
// free heap; later calls return the cached result. Returns false if any step
// failed, in which case BT mode must not be entered.
bool ble_tx_init();

// True once ble_tx_init() has succeeded.
bool ble_tx_ready();

// True while a previous put/stop is still waiting for the controller's
// completion event. The scheduler must not call ble_tx_put() while busy.
bool ble_tx_busy();

// Result of ble_tx_put().
enum BlePut : uint8_t {
    BLE_PUT_OK = 0,      // the message is going on the air
    BLE_PUT_SWITCHING,   // another slot was on the air: advertising is being
                         // stopped so the address can change. Retry as soon as
                         // ble_tx_busy() clears; this is normal with 2+ drones.
    BLE_PUT_BUSY,        // a previous request is still pending, or not ready
    BLE_PUT_ERROR        // a GAP call failed (printed)
};

// Put one ASTM message on the air for virtual drone `slot`, replacing
// whatever was advertised before. Sets the slot's address and starts
// advertising on the first call (or after a stop); afterwards, for the same
// slot, it only replaces the advertising data.
BlePut ble_tx_put(uint8_t slot, const uint8_t msg[F3411_MSG_BYTES], uint8_t counter);

// Stop advertising. Safe to call when not started.
void ble_tx_stop();

// Stop advertising only if slot `slot` is the one on the air. Used when one
// drone of several leaves the air, so the others are not interrupted.
void ble_tx_stop_slot(uint8_t slot);

// Change the advertising interval at runtime (units of 0.625 ms, HCI range
// 0x0020..0x4000). Takes effect at the next advertising start: if
// advertising, it is stopped now and the scheduler's next put restarts it.
// Returns false if out of range or not ready.
bool     ble_tx_set_interval(uint16_t units);
uint16_t ble_tx_interval();

// This slot's BLE address, most significant octet first, for logging.
const uint8_t *ble_tx_addr(uint8_t slot);

// Counters for `radio status`: messages put, GAP errors reported by events,
// and address changes (advertising stopped to switch drone).
uint32_t ble_tx_puts();
uint32_t ble_tx_errors();
uint32_t ble_tx_switches();
