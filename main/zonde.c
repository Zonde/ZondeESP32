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

// Set these parameters with `make menuconfig`
#define HOP_INTERVAL            CONFIG_CHANNEL_HOP_INTERVAL
#define DEAUTH_INTERVAL         CONFIG_DEAUTH_INTERVAL
#define SNIFF_INTERVAL          (CONFIG_SNIFF_INTERVAL*1000)

// Indicates it is safe to switch wifi modes
#define CAN_SWITCH_BIT          BIT3

void wait_millis(unsigned int millis) {
    vTaskDelay(millis / portTICK_PERIOD_MS);
}

void wifi_mode_task(void *pvParameter) {
    wifi_initialize();
    xEventGroupSetBits(wifi_event_group, CAN_SWITCH_BIT);
    sniffer_init();
    
    while(true) {
        ESP_LOGI("wifi_mode", "Setting mode: SNIFF");
        wifi_sniff(&sniffer_callback);
        wait_millis(SNIFF_INTERVAL);
        ESP_LOGI("wifi_mode", "Setting mode: STA");
        xEventGroupWaitBits(wifi_event_group, CAN_SWITCH_BIT, false, true, portMAX_DELAY);
        wifi_sta();
        xEventGroupSetBits(wifi_event_group, UPLOADING_BIT);
        // TODO Wait for about 10 seconds, if not connected skip uploading this time
        xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, portMAX_DELAY);
        upload_results();
        xEventGroupClearBits(wifi_event_group, UPLOADING_BIT);
    }
}

void channel_hop_task(void *pvParameter) {
    while(true) {
        xEventGroupWaitBits(wifi_event_group, AP_MODE_BIT, false, true, portMAX_DELAY);
        wifi_channel_hop();
        //ESP_LOGI("channel_hop", "Hopped to channel: %d", wifi_get_sniff_channel());
        wait_millis(HOP_INTERVAL);
    }
}

void deauth_task(void *pvParameter) {
    wifi_deauth_init();
    while(true) {
        xEventGroupWaitBits(wifi_event_group, AP_MODE_BIT, false, true, portMAX_DELAY);
        xEventGroupClearBits(wifi_event_group, CAN_SWITCH_BIT);
        ESP_LOGI("deauth", "Sending deauth wave");
        wifi_deauth();
        xEventGroupSetBits(wifi_event_group, CAN_SWITCH_BIT);
        wait_millis(DEAUTH_INTERVAL);
    }
}

void app_main() {
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    event_handler_init();


    xTaskCreate(&wifi_mode_task, "wifi_mode_task", 5000, NULL, 5, NULL);
    xTaskCreate(&channel_hop_task, "channel_hop_task", 5000, NULL, 5, NULL);
#ifdef CONFIG_JAM_ENABLED
    xTaskCreate(&deauth_task, "deauth_task", 5000, NULL, 5, NULL);
#endif
}

