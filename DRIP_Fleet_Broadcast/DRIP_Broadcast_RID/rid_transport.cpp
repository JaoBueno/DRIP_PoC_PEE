#include "rid_transport.h"
#include "beacon_tx_raw.h"
#include "ble_tx.h"
#include <Arduino.h>

static RidRadio g_radio = RID_RADIO_WIFI;

void rid_transport_init() {
    beacon_tx_raw_init();          // unchanged Wi-Fi bring-up
    g_radio = RID_RADIO_WIFI;
}

RidRadio rid_transport_active() { return g_radio; }

const char *rid_transport_name(RidRadio r) {
    return (r == RID_RADIO_BT) ? "Bluetooth Legacy (ASTM F3411-22a 5.4.6)"
                               : "Wi-Fi Beacon (ASTM F3411-22a 5.4.9)";
}

bool rid_transport_select(RidRadio r) {
    if (r == g_radio) return true;

    if (r == RID_RADIO_BT) {
        // Start BT before stopping Wi-Fi, so a controller failure leaves the
        // bench exactly as it was.
        if (!ble_tx_init()) {
            Serial.println("[Radio] Bluetooth failed to start - staying on Wi-Fi.");
            return false;
        }
        beacon_tx_raw_suspend();
        g_radio = RID_RADIO_BT;
    } else {
        ble_tx_stop();
        beacon_tx_raw_resume();
        g_radio = RID_RADIO_WIFI;
    }
    Serial.printf("[Radio] active transport: %s\n", rid_transport_name(g_radio));
    return true;
}

void rid_transport_send_pack(uint8_t slot, const MessagePack *pack, uint8_t msg_counter) {
    if (g_radio == RID_RADIO_WIFI) beacon_tx_raw_send(slot, pack, msg_counter);
}

void rid_transport_repeat(uint8_t slot) {
    if (g_radio == RID_RADIO_WIFI) beacon_tx_raw_repeat(slot);
}

BlePut rid_transport_put_legacy(uint8_t slot, const uint8_t msg[F3411_MSG_BYTES],
                                uint8_t counter) {
    if (g_radio != RID_RADIO_BT) return BLE_PUT_BUSY;
    return ble_tx_put(slot, msg, counter);
}

bool rid_transport_legacy_busy() {
    return (g_radio == RID_RADIO_BT) ? ble_tx_busy() : false;
}

void rid_transport_stop(uint8_t slot) {
    if (g_radio == RID_RADIO_WIFI) beacon_tx_raw_stop(slot);
    else                           ble_tx_stop_slot(slot);   // only if it is this slot on the air
}

const uint8_t *rid_transport_addr(uint8_t slot) {
    return (g_radio == RID_RADIO_BT) ? ble_tx_addr(slot) : beacon_tx_raw_mac(slot);
}
