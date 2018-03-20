#include "event_handler.h"

#include "esp_wifi.h"
#include "esp_log.h"

static esp_err_t event_handler(void *ctx, system_event_t *event);

void event_handler_init() {
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
    wifi_event_group = xEventGroupCreate();
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    uint8_t* mac;
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_STA_START");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_STA_GOT_IP");
            ESP_LOGI("event_handler", "Got IP: %s\n",
                     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
            xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_STA_DISCONNECTED");
            xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
            // Try to reconnect if we get thrown off trying to upload our results
            if(xEventGroupGetBits(wifi_event_group) & UPLOADING_BIT) {
                ESP_ERROR_CHECK(esp_wifi_connect());
            }
            break;

        case SYSTEM_EVENT_AP_START:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_AP_START");
            xEventGroupSetBits(wifi_event_group, AP_MODE_BIT);
            break;

        case SYSTEM_EVENT_AP_STOP:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_AP_STOP");
            xEventGroupClearBits(wifi_event_group, AP_MODE_BIT);
            break;

        case SYSTEM_EVENT_AP_STACONNECTED:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_AP_STACONNECTED");
            mac = event->event_info.sta_connected.mac;
            ESP_LOGI("event_handler", "Connected client MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            break;

        case SYSTEM_EVENT_AP_STADISCONNECTED:
            ESP_LOGI("event_handler", "SYSTEM_EVENT_AP_STADISCONNECTED");
            mac = event->event_info.sta_disconnected.mac;
            ESP_LOGI("event_handler", "Disconnected client MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            // Close any sockets still open
            break;

        default:
            break;
    }
    return ESP_OK;
}
