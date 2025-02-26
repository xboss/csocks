#include "ssconn.h"


// ssbuffer start

ssbuffer_t* ssbuffer_init() {
    ssbuffer_t* ssb = (ssbuffer_t*)calloc(1, sizeof(ssbuffer_t));
    if (!ssb) {
        return NULL;
    }
    return ssb;
}

void ssbuffer_free(ssbuffer_t* ssb) {
    if (ssb) {
        if (ssb->buf) {
            free(ssb->buf);
            ssb->buf = NULL;
        }
        free(ssb);
    }
}

int ssbuffer_grow(ssbuffer_t* ssb, int len) {
    assert(len >= 0);
    if (ssb->len + len > ssb->cap) {
        int new_cap = ssb->cap * 3 / 2;
        if (new_cap < ssb->len + len) {
            new_cap = ssb->len + len;
        }
        char* new_buf = (char*)calloc(1, new_cap);
        if (!new_buf) {
            return _ERR;
        }
        if (ssb->buf) {
            memcpy(new_buf, ssb->buf, ssb->len);
            free(ssb->buf);
        }
        ssb->buf = new_buf;
        ssb->cap = new_cap;
    }
    return _OK;
}

// ssbuffer end

// ssconn start



static void on_close(uv_handle_t* handle) {
    free(handle);
}

ssconn_t* ssconn_init(uv_stream_t* tcp, ssconn_type_t type, ssconn_st_t status) {
    
    return NULL;
    /* TODO: */
}

void ssconn_free(ssconn_t* conn){
    /* TODO: */
}

void ssconn_free_all(){
    /* TODO: */
}

ssconn_t* ssconn_get(int fd){
    /* TODO: */
    return NULL;
}

int ssconn_close(int fd){
    /* TODO: */
    return _OK;
}

int ssconn_send(int fd, const char* buf, int len){
    /* TODO: */
    return _OK;
}

// int ssconn_flush_send_buf(ssconn_t* cp_conn){
//     /* TODO: */
//     return _OK;
// }

// ssconn end