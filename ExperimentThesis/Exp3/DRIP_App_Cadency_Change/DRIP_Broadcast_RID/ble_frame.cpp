#include "ble_frame.h"
#include <string.h>

// ASTM F3411-22a §5.4.6.4 (BB40030) / Table 14 — see ble_frame.h for the layout.
void ble_build_legacy_adv(const uint8_t msg[F3411_MSG_BYTES], uint8_t counter,
                          uint8_t out[ODID_BT_LEGACY_ADV_BYTES]) {
    out[0] = ODID_BT_AD_LEN;           // 0x1E
    out[1] = ODID_BT_AD_TYPE_SVC16;    // 0x16
    out[2] = ODID_BT_UUID_LO;          // 0xFA
    out[3] = ODID_BT_UUID_HI;          // 0xFF
    out[4] = ODID_BT_APP_CODE;         // 0x0D
    out[5] = counter;                  // ASTM §5.4.4.2
    memcpy(&out[6], msg, F3411_MSG_BYTES);
}
