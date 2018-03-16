#ifndef ACCESSPOINT_COLLECTOR_H
#define ACCESSPOINT_COLLECTOR_H


#include "wifi.h"

typedef struct {
    uint8_t source_mac[6];
} Beacon;

void add_beacon(Beacon *b);
int get_beacons_length();
Beacon get_beacon(int index);

#endif
