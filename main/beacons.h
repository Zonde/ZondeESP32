#ifndef BEACONS_H
#define BEACONS_H

#include "set.h"
#include <stdint.h>

typedef struct {
    uint8_t source_mac[6];
} Beacon;

SET_DEF(Beacon)

Beacon_set sniffed_beacons;

#endif
