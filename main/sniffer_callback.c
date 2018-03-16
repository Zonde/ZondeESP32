#include "sniffer_callback.h"

#include "esp_log.h"

#include <string.h>

typedef struct {
    unsigned version:2;
    unsigned type:2;
    unsigned subtype:4;
    uint8_t flags;
} __packed __aligned(2) frame_ctrl_header;

typedef struct {
    frame_ctrl_header frame_ctrl;
    unsigned duration_id:16;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* filtering address */
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; /* optional */
} __packed __aligned(2) wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0];
} __packed __aligned(2) wifi_ieee80211_packet_t;

#define PROBE_BUFFER_LEN 100
static Probe probes[PROBE_BUFFER_LEN];
static unsigned int probes_len = 0;

unsigned int get_probes(Probe** p) {
    *p = probes;
    return probes_len;
}

void clear_probes() {
    probes_len = 0;
}

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Filter on probe requests
    if(hdr->frame_ctrl.subtype != 0x04) {
        return;
    }

    uint8_t* payload = (uint8_t*) ppkt->payload;
    int body_len = ppkt->rx_ctrl.sig_len - 28;
    uint8_t* body = payload + 24;

    int i = 0;
    while(i < body_len) {
        uint8_t length = body[i+1];
        if(body[i] == 0) {
            // SSID
            if(length > 0) {
                if(probes_len == PROBE_BUFFER_LEN) {
                    ESP_LOGW("sniffer_callback", "probes buffer exhausted");
                    return;
                }
                Probe* p = probes + probes_len++;
                memcpy(p->transmitter, hdr->addr2, 6);
                memcpy(p->ssid, body+i+2, length);
                p->ssid[length] = '\0';

                ESP_LOGI("sniffer_callback", "MAC: %02x:%02x:%02x:%02x:%02x:%02x, SSID: %s\n",
                p->transmitter[0], p->transmitter[1], p->transmitter[2],
                p->transmitter[3], p->transmitter[4], p->transmitter[5],
                p->ssid);
            }
            // TODO parse more
        }
        i += 2 + length;
    }
}
