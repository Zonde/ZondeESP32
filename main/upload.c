#include "upload.h"
#include "esp_log.h"
#include "probes.h"

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
        ESP_LOGI("upload_results", "Uploading: %s", postfields);
        request_t* req = req_new("http://zonde.herokuapp.com/api/post/");
        req_setopt(req, REQ_SET_METHOD, "POST");
        req_setopt(req, REQ_SET_POSTFIELDS, postfields);
        req_setopt(req, REQ_FUNC_DOWNLOAD_CB, upload_callback);
        int status = req_perform(req);
        req_clean(req);
        ESP_LOGI("upload", "Status code: %d", status);
    }
    Probe_set_clear(sniffed_probes);
}
