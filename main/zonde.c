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

#include "event_handler.h"
#include "wifi.h"
#include "upload.h"
#include "wifi_deauth.h"
#include "sniffer_callback.h"

void wifi_manager(void *pvParameter)
{
    wifi_initialize();
    sniffer_init();
    while(true) {
        ESP_LOGI("wifi_manager", "Setting mode: SNIFF");
        wifi_sniff(sniffer_callback);
        for(int i = 0; i < SNIFF_INTERVAL/HOP_INTERVAL; i++) {
            vTaskDelay(HOP_INTERVAL / portTICK_PERIOD_MS);
            wifi_channel_hop();
            #ifdef CONFIG_JAM_ENABLED
                wifi_deauth();
            #endif
        }

        ESP_LOGI("wifi_manager", "Setting mode: STA");
        wifi_sta();

        xEventGroupSetBits(wifi_event_group, UPLOADING_BIT);
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
        upload_results();
        xEventGroupClearBits(wifi_event_group, UPLOADING_BIT);
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
    ESP_ERROR_CHECK(ret);

    event_handler_init();

    xTaskCreate(&wifi_manager, "wifi_manager", 5000, NULL, 5, NULL);
}
