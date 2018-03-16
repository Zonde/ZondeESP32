#ifndef PROBES_H
#define PROBES_H

#include "set.h"
#include <stdint.h>

typedef struct {
    uint8_t transmitter[6];
    char ssid[33];
} Probe;

SET_DEF(Probe)

Probe_set sniffed_probes;
#endif
