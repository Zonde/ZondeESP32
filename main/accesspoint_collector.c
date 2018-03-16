#include "accesspoint_collector.h"

#include "esp_log.h"

#include <string.h>


#define BEACON_BUFFER_SIZE 100

static unsigned int beacons_len = 0;
static Beacon beacons[BEACON_BUFFER_SIZE];

void add_beacon(Beacon *b) {
    if (beacons_len == BEACON_BUFFER_SIZE) {
        ESP_LOGW("accesspoint_collector", "beacons buffer exhausted");
        return;
    }

    for (int i = 0; i < beacons_len; i++) {
        if (memcmp(b->source_mac, beacons[i].source_mac, 6) == 0) {
            ESP_LOGI("accesspoint_collector", "double entry found");
            return;
        }
    }

    memcpy(beacons[beacons_len].source_mac, b->source_mac, 6);
    beacons_len++;
    ESP_LOGI("accesspoint_collector", "added to beacon buffer: %02x:%02x:%02x:%02x:%02x:%02x",
        b->source_mac[0],b->source_mac[1],b->source_mac[2],b->source_mac[3],b->source_mac[4],b->source_mac[5])
}
