#ifndef UPLOAD_H
#define UPLOAD_H

#include "esp_wifi.h"
#include "esp_request.h"
#include "sniffer_callback.h"

void upload_callback(request_t* req, char* data, int len);
void upload_results(Probe* probes, unsigned int len);

#endif
