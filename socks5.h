#ifndef _SOCKS5_H
#define _SOCKS5_H

#include "ss5.h"
#include "ssconn.h"
#include "tcp_server.h"

typedef struct {
    uv_loop_t* loop;
    ssconfig_t *conf;
    tcp_server_t *tcp_server;
} socks5_t;

socks5_t* socks5_init(uv_loop_t* loop, ssconfig_t* conf);
void socks5_free(socks5_t* socks5);
int socks5_start(socks5_t* socks5);

// int ss5_auth(ssconn_t* conn, const char* buf, int len);
// int ss5_auth_np(ssconn_t* conn, const char* buf, int len);
// int ss5_req(ssconn_t* conn, const char* buf, int len);
// int ss5_data(ssconn_t* conn, const char* buf, int len, int tag_len);

#endif /* _SOCKS5_H */