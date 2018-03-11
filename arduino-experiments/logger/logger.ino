/**
 * Keeps a set of unique sniffed MAC/SSID pairs and prints them to Serial
 * Proof of concept that we can capture and analyse probe requests on the ESP32
 *
 * Author: Daan de Graaf
 */

#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#include <set>

#include <WiFi.h>
#include <WiFiMulti.h>

WiFiMulti WiFiMulti;

#define CHANNEL 1
#define BAUD_RATE 115200
#define CHANNEL_HOPPING true 
#define MAX_CHANNEL 11 
#define HOP_INTERVAL 214 

int ch = CHANNEL;
unsigned long lastChannelChange = 0;

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

struct Probe {
    uint8_t transmitter[6];
    char ssid[33];
};

inline bool operator<(const Probe& lhs, const Probe& rhs)
{
    for(int i = 0; i < 6; i++) {
        if(lhs.transmitter[i] != rhs.transmitter[i]) {
            return lhs.transmitter[i] < rhs.transmitter[i];
        }
    }
    return strcmp(lhs.ssid, rhs.ssid) < 0;
}

std::set<Probe> probes;

void sniffer(void *buff, wifi_promiscuous_pkt_type_t type){
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Filter on probe requests
    if(hdr->frame_ctrl.subtype != 0x04) {
        return;
    }

    uint8_t* payload = (uint8_t*) ppkt->payload;
    int body_len = ppkt->rx_ctrl.sig_len - 28;
    uint8_t* body = payload + 24;

    char ssid[33];
    int i = 0;
    while(i < body_len) {
        uint8_t length = body[i+1];
        if(body[i] == 0) {
            // SSID
            if(length > 0) {
                Probe* p = new Probe;
                memcpy(p->transmitter, hdr->addr2, 6);
                memcpy(p->ssid, body+i+2, length);
                p->ssid[length] = '\0';

                int old_size = probes.size();
                probes.insert(*p);
                int new_size = probes.size();

                if(new_size > old_size) {
                    Serial.printf("Number of unique probes: %d\n", new_size);
                    for(Probe p : probes) {
                        Serial.printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x, SSID: %s\n", 
                        p.transmitter[0], p.transmitter[1], p.transmitter[2], 
                        p.transmitter[3], p.transmitter[4], p.transmitter[5], 
                        p.ssid);
                    }
                }
            }
        }
        i += 2 + length;
    }
}

esp_err_t event_handler(void *ctx, system_event_t *event){ 
    return ESP_OK; 
}

void setup() {
    /* start Serial */
    Serial.begin(BAUD_RATE);
    delay(2000);
    Serial.println();

    Serial.println("<<START>>");

    /* setup wifi */
    nvs_flash_init();
    tcpip_adapter_init();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_AP) );  
    ESP_ERROR_CHECK( esp_wifi_start() );
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer);
    wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
    esp_wifi_set_channel(ch,secondCh);
}

void loop() {
    if(CHANNEL_HOPPING){
        unsigned long currentTime = millis();
        if(currentTime - lastChannelChange >= HOP_INTERVAL){
            lastChannelChange = currentTime;
            ch++; 
            if(ch > MAX_CHANNEL) ch = 1;
            wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
            esp_wifi_set_channel(ch,secondCh);
        }
    }

    /*
    esp_wifi_stop();

    Serial.println("Stopped!");

    WiFiMulti.addAP("Wildarch", "dikkepech");
    while(WiFiMulti.run() != WL_CONNECTED) {
        Serial.print(".");
        delay(500);
    }

    Serial.println("");
    Serial.println("WiFi connected");
    Serial.println("IP address: ");
    Serial.println(WiFi.localIP());
    */
    
}
