#include "tcp_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// callback start

static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    tcp_server_t* tcp_server = (tcp_server_t*)handle->data;
    assert(tcp_server);
    if (tcp_server->read_buf_size > 0) suggested_size = tcp_server->read_buf_size;
    buf->base = (char*)calloc(1, suggested_size);
    if (!buf->base) {
        _LOG_E("Failed to allocate memory for buffer");
        buf->len = 0;
    } else {
        buf->len = suggested_size;
    }
}

static void on_close(uv_handle_t* tcp) {
    tcp_server_t* tcp_server = (tcp_server_t*)tcp->data;
    assert(tcp_server);
    if (tcp_server->on_close) {
        tcp_server->on_close(tcp);
    }
    free(tcp);
}

static void on_read(uv_stream_t* tcp, ssize_t nread, const uv_buf_t* buf) {
    uv_os_fd_t fd;
    if (uv_fileno((const uv_handle_t*)tcp, &fd) != 0) {
        _LOG_E("Failed to get fd");
        uv_close((uv_handle_t*)tcp, on_close);
        return;
    }
    _LOG("Read %d bytes from front fd: %d", (int)nread, (int)fd);

    if (nread < 0) {
        if (nread != UV_EOF) {
            _LOG_E("Read error %s", uv_err_name(nread));
        }
        uv_close((uv_handle_t*)tcp, on_close);
        free(buf->base);
        return;
    }

    if (nread > 0) {
        tcp_server_t* tcp_server = (tcp_server_t*)tcp->data;
        assert(tcp_server);
        if (tcp_server->on_read) {
            tcp_server->on_read(tcp, buf->base, nread);
        }
    }
    free(buf->base);
}

static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        _LOG_E("New connection error %s", uv_strerror(status));
        return;
    }

    uv_tcp_t* client = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    if (!client) {
        _LOG_E("Failed to allocate memory for client");
        return;
    }

    if (uv_tcp_init(server->loop, client) != 0) {
        _LOG_E("Failed to initialize client");
        free(client);
        return;
    }

    if (uv_accept(server, (uv_stream_t*)client) != 0) {
        _LOG_E("uv_accept error");
        uv_close((uv_handle_t*)client, on_close);
        return;
    }

    uv_os_fd_t client_fd, server_fd;
    if (uv_fileno((const uv_handle_t*)client, &client_fd) != 0 || uv_fileno((const uv_handle_t*)server, &server_fd) != 0) {
        _LOG_E("Failed to get client fd");
        uv_close((uv_handle_t*)client, on_close);
        return;
    }
    _LOG("Accepted client fd: %d server fd: %d", (int)client_fd, (int)server_fd);

    tcp_server_t* tcp_server = (tcp_server_t*)server->data;
    assert(tcp_server);
    client->data = tcp_server;
    if (tcp_server->on_accept) {
        tcp_server->on_accept((uv_stream_t*)client);
    }
    uv_read_start((uv_stream_t*)client, alloc_buffer, on_read);
}

// callback end

tcp_server_t* tcp_server_init(uv_loop_t* loop, const char* listen_ip, unsigned short listen_port, int read_buf_size) {
    if (!loop || !listen_ip || listen_port <= 0) return NULL;
    tcp_server_t* tcp_server = (tcp_server_t*)calloc(1, sizeof(tcp_server_t));
    if (!tcp_server) return NULL;
    tcp_server->loop = loop;
    if (read_buf_size > 0) tcp_server->read_buf_size = read_buf_size;
    strncpy(tcp_server->listen_ip, listen_ip, INET_ADDRSTRLEN);
    tcp_server->listen_port = listen_port;
    return tcp_server;
}

void tcp_server_free(tcp_server_t* tcp_server) {
    if (!tcp_server) return;
    if (tcp_server->server) {
        uv_close((uv_handle_t*)tcp_server->server, NULL);
        free(tcp_server->server);
        tcp_server->server = NULL;
    }
    free(tcp_server);
    return;
}

int tcp_server_start(tcp_server_t* tcp_server) {
    if (!tcp_server) return _ERR;

    tcp_server->server = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    if (!tcp_server->server) return _ERR;

    if (uv_tcp_init(tcp_server->loop, tcp_server->server) != 0) {
        _LOG_E("Failed to initialize server");
        free(tcp_server->server);
        tcp_server->server = NULL;
        return _ERR;
    }

    struct sockaddr_in addr;
    if (uv_ip4_addr(tcp_server->listen_ip, tcp_server->listen_port, &addr) != 0) {
        _LOG_E("Invalid IP address or port");
        free(tcp_server->server);
        tcp_server->server = NULL;
        return _ERR;
    }

    tcp_server->server->data = tcp_server;
    if (uv_tcp_bind(tcp_server->server, (const struct sockaddr*)&addr, 0) != 0) {
        _LOG_E("Failed to bind server");
        free(tcp_server->server);
        tcp_server->server = NULL;
        return _ERR;
    }

    int rt = uv_listen((uv_stream_t*)tcp_server->server, 128, on_new_connection);
    if (rt) {
        _LOG_E("Listen error %s", uv_strerror(rt));
        uv_close((uv_handle_t*)tcp_server->server, NULL);
        free(tcp_server->server);
        tcp_server->server = NULL;
        return _ERR;
    }

    return _OK;
}
