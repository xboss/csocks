#ifndef _TCP_SERVER_H
#define _TCP_SERVER_H

#include "ss5.h"

typedef int (*tcp_server_accept_cb_t)(uv_stream_t* server);

typedef struct {
    uv_loop_t* loop;
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    uv_tcp_t *server;
    int read_buf_size;
    int (*on_accept)(uv_stream_t* tcp);
    int (*on_read)(uv_stream_t* tcp, const char* buf, int len);
    void (*on_close)(uv_handle_t* tcp);
} tcp_server_t;

tcp_server_t* tcp_server_init(uv_loop_t* loop, const char* listen_ip, unsigned short listen_port, int read_buf_size);
void tcp_server_free(tcp_server_t* tcp_server);
int tcp_server_start(tcp_server_t* tcp_server);
// void tcp_server_close(tcp_server_t* tcp_server, int fd);

#endif /* _TCP_SERVER_H */