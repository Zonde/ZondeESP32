/**
 * Dumps 802.11 probe request payloads to the serial
 * 
 * The start of data is marked by sending <<START>>
 * Then for each packet:
 *   The length of the packet is sent (uint32_t)
 *   The data is sent (little-endian)
 *
 * Author: Daan de Graaf
 */

#include "esp_wifi.h"
#include "esp_wifi_internal.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"

#define CHANNEL 1
#define MAX_CHANNEL 11
#define BAUD_RATE 115200
#define CHANNEL_HOPPING true
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

/* Callback for received packets */
void sniffer(void *buff, wifi_promiscuous_pkt_type_t type){
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
    const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Verify that this is a probe request
    if(hdr->frame_ctrl.subtype != 0x04) {
        return;
    }

    uint32_t len = ppkt->rx_ctrl.sig_len;
    uint8_t* bytes = (uint8_t*) &len;
    for(int i = 0; i < 4; i++) {
        Serial.write(bytes[i]);
    }
    
    bytes = (uint8_t*) ppkt->payload;
    for(uint32_t i = 0; i < len; i++) {
        Serial.write(bytes[i]);
    }
    
}

esp_err_t event_handler(void *ctx, system_event_t *event){ return ESP_OK; }


void setup() {

    Serial.begin(BAUD_RATE);
    delay(2000);
    Serial.println();

    Serial.println("<<START>>");

    // Setup wifi
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
    if(CHANNEL_HOPPING) {
        unsigned long currentTime = millis();
        if(currentTime - lastChannelChange >= HOP_INTERVAL){
            lastChannelChange = currentTime;
            ch++;
            if(ch > MAX_CHANNEL) ch = 1;
            wifi_second_chan_t secondCh = (wifi_second_chan_t)NULL;
            esp_wifi_set_channel(ch,secondCh);
        }
    }
}
