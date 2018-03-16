#ifndef ACCESSPOINT_COLLECTOR_H
#define ACCESSPOINT_COLLECTOR_H

#include "esp_wifi.h"

typedef struct {
    uint8_t source_mac[6];
} Beacon;

void add_beacon(Beacon *b);
