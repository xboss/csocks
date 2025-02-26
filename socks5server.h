#ifndef _SOCKS5SERVER_H
#define _SOCKS5SERVER_H

#include "ss5.h"
#include "tcp_server.h"

typedef struct {
    uv_loop_t* loop;
    ssconfig_t *conf;
    tcp_server_t *tcp_server;
} socks_t;

socks_t* socks_init(uv_loop_t* loop, ssconfig_t* conf);
void socks_free(socks_t* socks);
int socks_start(socks_t* socks);
// void socks_stop(socks_t* socks);

#endif /* _SOCKS5SERVER_H */