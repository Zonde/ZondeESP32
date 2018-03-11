/* Zonde sniffer

    This code is in the Public Domain (or CC0 licensed, at your option.)

    Unless required by applicable law or agreed to in writing, this
    software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
    CONDITIONS OF ANY KIND, either express or implied.
*/
/*
    Sniffer application for ESP32. 
    Sniffs probe requests and periodically connects to the configured SSID
    to upload results to a remote server.

    Author: Daan de Graaf
*/
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "esp_log.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#include <string.h>

// Set these parameters with `make menuconfig`
#define DEFAULT_SSID            CONFIG_WIFI_SSID
#define DEFAULT_PWD             CONFIG_WIFI_PASSWORD
#define HOP_INTERVAL            CONFIG_CHANNEL_HOP_INTERVAL
#define SNIFF_INTERVAL          (CONFIG_SNIFF_INTERVAL*1000)

#define DEFAULT_SCAN_METHOD     WIFI_FAST_SCAN
#define DEFAULT_SORT_METHOD     WIFI_CONNECT_AP_BY_SIGNAL
#define DEFAULT_RSSI            -127
#define DEFAULT_AUTHMODE        WIFI_AUTH_OPEN

#define MIN_CHANNEL             1
#define MAX_CHANNEL             11
#define SECOND_CHANNEL          (wifi_second_chan_t)NULL


static const char *TAG = "sniffer";
static int sniffChan = MIN_CHANNEL; 

typedef struct {
    unsigned version:2;
    unsigned type:2;
    unsigned subtype:4;
    uint8_t flags;
} __packed __aligned(2) frame_ctrl_header;

typedef struct {
    frame_ctrl_header frame_ctrl;
    unsigned duration_id:16;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; /* optional */
} __packed __aligned(2) wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; 
} __packed __aligned(2) wifi_ieee80211_packet_t;

typedef struct {
    uint8_t transmitter[6];
    char ssid[33];
} Probe;

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    uint8_t* mac;
    switch (event->event_id) {
        case SYSTEM_EVENT_STA_START:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_START");
            ESP_ERROR_CHECK(esp_wifi_connect());
            break;
        case SYSTEM_EVENT_STA_GOT_IP:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_GOT_IP");
            ESP_LOGI(TAG, "Got IP: %s\n",
                     ip4addr_ntoa(&event->event_info.got_ip.ip_info.ip));
            break;
        case SYSTEM_EVENT_STA_DISCONNECTED:
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
            break;

        case SYSTEM_EVENT_AP_START:
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_START");
            break;

        case SYSTEM_EVENT_AP_STOP:
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STOP");
            break;

        case SYSTEM_EVENT_AP_STACONNECTED:
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STACONNECTED");
            mac = event->event_info.sta_connected.mac;
            ESP_LOGI(TAG, "Connected client MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            break;

        case SYSTEM_EVENT_AP_STADISCONNECTED:
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STADISCONNECTED");
            mac = event->event_info.sta_disconnected.mac;
            ESP_LOGI(TAG, "Disconnected client MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            // Close any sockets still open
            break;

        default:
            break;
    }
    return ESP_OK;
}

/* Initialize Wi-Fi as sta */
static void wifi_sta(void)
{
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = DEFAULT_SSID,
            .password = DEFAULT_PWD,
            .scan_method = DEFAULT_SCAN_METHOD,
            .sort_method = DEFAULT_SORT_METHOD,
            .threshold.rssi = DEFAULT_RSSI,
            .threshold.authmode = DEFAULT_AUTHMODE,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(false));
}

static void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Filter on probe requests
    if(hdr->frame_ctrl.subtype != 0x04) {
        return;
    }

    uint8_t* payload = (uint8_t*) ppkt->payload;
    int body_len = ppkt->rx_ctrl.sig_len - 28;
    uint8_t* body = payload + 24;

    int i = 0;
    while(i < body_len) {
        uint8_t length = body[i+1];
        if(body[i] == 0) {
            // SSID
            if(length > 0) {
                Probe p;
                memcpy(p.transmitter, hdr->addr2, 6);
                memcpy(p.ssid, body+i+2, length);
                p.ssid[length] = '\0';

                ESP_LOGI("sniffer_callback", "MAC: %02x:%02x:%02x:%02x:%02x:%02x, SSID: %s\n", 
                p.transmitter[0], p.transmitter[1], p.transmitter[2], 
                p.transmitter[3], p.transmitter[4], p.transmitter[5], 
                p.ssid);
            }
            // TODO parse more
        }
        i += 2 + length;
    }
}

/* Initialize Wi-Fi as sniffer */
static void wifi_sniff(void)
{
    wifi_config_t wifi_config = {
        .ap = {
            .ssid_hidden = true,
        }
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer_callback);
    sniffChan = MIN_CHANNEL;
    esp_wifi_set_channel(sniffChan, SECOND_CHANNEL);
}

static void wifi_init(void)
{
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
}

void wifi_manager(void *pvParameter) {
    wifi_init();
    while(true) {
        ESP_LOGI("wifi_manager", "Setting mode: STA");
        wifi_sta();

        // Do stuff here instead
        vTaskDelay(5000 / portTICK_PERIOD_MS);
        
        ESP_LOGI("wifi_manager", "Setting mode: SNIFF");
        wifi_sniff();
        for(int i = 0; i < SNIFF_INTERVAL/HOP_INTERVAL; i++) {
            vTaskDelay(HOP_INTERVAL / portTICK_PERIOD_MS);
            sniffChan++;
            if(sniffChan > MAX_CHANNEL) {
                sniffChan = MIN_CHANNEL;
            }
            esp_wifi_set_channel(sniffChan, SECOND_CHANNEL);
        }
    }
}

void app_main()
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    xTaskCreate(&wifi_manager, "wifi_manager", 5000, NULL, 5, NULL);
}
