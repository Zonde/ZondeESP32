#ifndef WIFI_H
#define WIFI_H

#include "esp_wifi.h"

#define DEFAULT_SSID            CONFIG_WIFI_SSID
#define DEFAULT_PWD             CONFIG_WIFI_PASSWORD
#define DEFAULT_SCAN_METHOD     WIFI_FAST_SCAN
#define DEFAULT_SORT_METHOD     WIFI_CONNECT_AP_BY_SIGNAL
#define DEFAULT_RSSI            -127
#define DEFAULT_AUTHMODE        WIFI_AUTH_OPEN

#define MIN_CHANNEL             1
#define MAX_CHANNEL             11
#define SECOND_CHANNEL          (wifi_second_chan_t)NULL

void wifi_initialize();

// Connect to an access point
void wifi_sta();

// Start hidden AP and sniff traffic
void wifi_sniff(wifi_promiscuous_cb_t cb);

// Hop to the next channel
void wifi_channel_hop();

int wifi_get_sniff_channel();

#endif
