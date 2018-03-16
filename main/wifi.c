#include "wifi.h"

static int sniffChan = MIN_CHANNEL;

void wifi_initialize(void)
{
    tcpip_adapter_init();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
}


void wifi_sta(void)
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

void wifi_sniff(wifi_promiscuous_cb_t cb)
{
    wifi_config_t wifi_config = {
        .ap = {
            .ssid_hidden = true,
        }
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Sniff traffic
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(cb);
    sniffChan = MIN_CHANNEL;
    esp_wifi_set_channel(sniffChan, SECOND_CHANNEL);
}

void wifi_channel_hop() {
    sniffChan++;
    if(sniffChan > MAX_CHANNEL) {
        sniffChan = MIN_CHANNEL;
    }
    ESP_ERROR_CHECK(esp_wifi_set_channel(sniffChan, SECOND_CHANNEL));
}

int wifi_get_sniff_channel() {
    return sniffChan;
}
