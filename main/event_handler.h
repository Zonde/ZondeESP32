#ifndef EVENT_HANDLER_H
#define EVENT_HANDLER_H

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_event_loop.h"

#define CONNECTED_BIT BIT0
#define UPLOADING_BIT BIT1

EventGroupHandle_t wifi_event_group;

void event_handler_init();

#endif
