#include "upload.h"
#include "esp_log.h"
#include "probes.h"

#define RETRY_COUNT 3

#ifdef CONFIG_SERVER_UPLOAD_ENDPOINT
#define SERVER_UPLOAD_ENDPOINT CONFIG_SERVER_UPLOAD_ENDPOINT
#else
#define SERVER_UPLOAD_ENDPOINT "http://zonde.herokuapp.com/api/post/"
#endif

void upload_callback(request_t* req, char* data, int len)
{
    ESP_LOGI("upload_callback", "%s", data);
}

void upload_results()
{
    Probe* probes = Probe_set_items(sniffed_probes);
    int len = Probe_set_size(sniffed_probes);
    for(unsigned int i = 0; i < len; i++) {
        // TODO I have no idea if this is really big enough
        char postfields[100];
        sprintf(postfields, "mac=%02x%%3A%02x%%3A%02x%%3A%02x%%3A%02x%%3A%02x&ssid=%s",
            probes[i].transmitter[0],
            probes[i].transmitter[1],
            probes[i].transmitter[2],
            probes[i].transmitter[3],
            probes[i].transmitter[4],
            probes[i].transmitter[5],
            probes[i].ssid
        );
        ESP_LOGI("upload_results", "Uploading: %s%s", SERVER_UPLOAD_ENDPOINT, postfields);
        for(int j = 0; j < RETRY_COUNT; j++) {
            request_t* req = req_new(SERVER_UPLOAD_ENDPOINT);
            req_setopt(req, REQ_SET_METHOD, "POST");
            req_setopt(req, REQ_SET_POSTFIELDS, postfields);
            req_setopt(req, REQ_FUNC_DOWNLOAD_CB, upload_callback);
            int status = req_perform(req);
            req_clean(req);
            ESP_LOGI("upload", "Status code: %d", status);
            if(status == 200) {
                break;
            }
        }
    }
    Probe_set_clear(sniffed_probes);
}
