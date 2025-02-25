#ifndef _SSCONN_H
#define _SSCONN_H

#include "ss5.h"

#include "uthash.h"

#define PACKET_HEAD_LEN 4

typedef struct {
    char* buf;  // 动态缓冲区
    int len;    // 当前缓冲长度
    int cap;    // 缓冲区容量
} ssbuffer_t;

ssbuffer_t* ssbuffer_init();
int ssbuffer_grow(ssbuffer_t* ssb, int len);
void ssbuffer_free(ssbuffer_t* ssb);

#define PACKET_HEAD_LEN 4
typedef enum { SSCONN_TYPE_NONE = 0, SSCONN_TYPE_SERV, SSCONN_TYPE_CLI } ssconn_type_t;
typedef enum { SSCONN_ST_OFF = 0, SSCONN_ST_WAIT, SSCONN_ST_ON } ssconn_st_t;
typedef enum { SSCONN_PHASE_NONE = 0, SSCONN_PHASE_AUTH, SSCONN_PHASE_REQ, SSCONN_PHASE_AUTH_NP, SSCONN_PHASE_DATA } ssconn_phase_t;
typedef struct {
    int fd;
    int cp_fd;
    uv_stream_t* tcp;
    ssconn_type_t type;
    ssconn_st_t status;
    ssconn_phase_t phase;
    ssbuffer_t* recv_buf;
    ssbuffer_t* send_buf;
    void* user_data;
    UT_hash_handle hh;
} ssconn_t;

ssconn_t* ssconn_init(uv_stream_t* tcp, ssconn_type_t type, ssconn_st_t status);
void ssconn_free(ssconn_t* conn);
void ssconn_free_all();
ssconn_t* ssconn_get(int fd);
int ssconn_close(int fd);
int ssconn_flush_send_buf(ssconn_t* cp_conn);

#endif /* _SSCONN_H */