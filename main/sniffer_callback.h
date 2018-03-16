#ifndef SNIFFER_CALLBACK_H
#define SNIFFER_CALLBACK_H

#include "esp_wifi.h"
#include "esp_wifi_internal.h"

typedef struct {
    uint8_t transmitter[6];
    char ssid[33];
} Probe;

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);

// TODO refactor me
unsigned int get_probes(Probe** p);
void clear_probes();

#endif
