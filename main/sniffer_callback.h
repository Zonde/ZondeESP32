#ifndef SNIFFER_CALLBACK_H
#define SNIFFER_CALLBACK_H

#include "esp_wifi.h"
#include "esp_wifi_internal.h"

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);

void sniffer_init();

#endif
