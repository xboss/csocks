#include "socks5server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "cipher.h"
#include "ssconn.h"
#include "socks5.h"

static char packet_tag[] = {'S', 'S', 'P'};

// callback start

static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)calloc(1, suggested_size);
    if (!buf->base) {
        _LOG_E("Failed to allocate memory for buffer");
        buf->len = 0;
    } else {
        buf->len = suggested_size;
    }
}

static void on_front_close(uv_handle_t* handle) {
    free(handle);
}

static void echo_write(uv_write_t* req, int status) {
    if (status) {
        _LOG_E("Write error %s", uv_strerror(status));
    }
    free(req);
}
static int on_front_read_ok(ssconn_t* conn, const char* buf, int len) {
    // check conn
    assert(conn);
    if (conn->status == SSCONN_ST_OFF) {
        _LOG_E("on_front_read_ok conn off");
        ssconn_close(conn->fd);
        return _ERR;
    }

    assert(conn->recv_buf);
    assert(conn->send_buf);

    socks_t* socks = (socks_t*)conn->tcp->loop->data;
    assert(socks);

    int rt = ssbuffer_grow(conn->recv_buf, len);
    if (rt != _OK) {
        _LOG_E("on_front_read_ok ssbuffer_grow recv_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->recv_buf->buf + conn->recv_buf->len, buf, len);
    conn->recv_buf->len += len;
    assert(conn->recv_buf->len > 0);

    // if (conn->status == SSCONN_ST_WAIT) {
    //     _LOG_E("on_front_read_ok conn waiting");
    //     return;
    // }

    int ciphertext_len = 0;
    int plain_text_len = 0;
    char* plain_text = NULL;
    while (conn->recv_buf->len > PACKET_HEAD_LEN) {
        // unpack
        ciphertext_len = ntohl(*(int*)conn->recv_buf->buf);
        if (ciphertext_len <= 0 || ciphertext_len > 65535) { /* TODO: magic number */
            _LOG_E("on_front_read_ok ciphertext_len:%d error. recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
            ssconn_close(conn->fd);
            return _ERR;
        }
        if (ciphertext_len > conn->recv_buf->len - PACKET_HEAD_LEN) {
            _LOG("on_front_read_ok ciphertext_len:%d > recv_buf->len:%d rfd:%d sfd:%d", ciphertext_len, conn->recv_buf->len, conn->fd, conn->cp_fd);
            return _OK;
        }
        // decrypt
        plain_text = aes_decrypt(socks->conf->key, conn->recv_buf->buf + PACKET_HEAD_LEN, ciphertext_len, &plain_text_len);
        if (plain_text == NULL) {
            _LOG_E("on_front_read_ok aes_decrypt error");
            ssconn_close(conn->fd);
            return _ERR;
        }

        assert(plain_text_len > sizeof(packet_tag));

        // check packet tag
        if (memcmp(plain_text + plain_text_len - sizeof(packet_tag), packet_tag, sizeof(packet_tag)) != 0) {
            _LOG_E("on_front_read_ok packet_tag error");
            ssconn_close(conn->fd);
            free(plain_text);
            return _ERR;
        }

        if (conn->phase == SSCONN_PHASE_AUTH) {
            rt = ss5_auth(conn, plain_text, plain_text_len - sizeof(packet_tag));
            if (rt != _OK) {
                _LOG_E("on_front_read_ok ss5_auth error");
                free(plain_text);
                return _ERR;
            }
        } else if (conn->phase == SSCONN_PHASE_AUTH_NP) {
            rt = ss5_auth_np(conn, plain_text, plain_text_len - sizeof(packet_tag));
            if (rt != _OK) {
                _LOG_E("on_front_read_ok ss5_auth_np error");
                free(plain_text);
                return _ERR;
            }
        } else if (conn->phase == SSCONN_PHASE_REQ) {
            ss5_req();
            /* TODO: */
        } else if (conn->phase == SSCONN_PHASE_DATA) {
            assert(conn->cp_fd > 0);
            assert(conn->status == SSCONN_ST_ON);
            rt = ss5_data(conn, plain_text, plain_text_len, sizeof(packet_tag));
            if (rt != _OK) {
                _LOG_E("on_front_read_ok ss5_data error");
                free(plain_text);
                return _ERR;
            }
        }
        free(plain_text);
    }
    return _OK;
}

static void on_front_read(uv_stream_t* front, ssize_t nread, const uv_buf_t* buf) {
    uv_os_fd_t front_fd;
    if (uv_fileno((const uv_handle_t*)front, &front_fd) != 0) {
        _LOG_E("Failed to get front fd");
        uv_close((uv_handle_t*)front, on_front_close);
        return;
    }
    _LOG("Read %d bytes from front fd: %d", (int)nread, (int)front_fd);

    if (nread < 0) {
        if (nread != UV_EOF) {
            _LOG_E("Read error %s", uv_err_name(nread));
        }
        uv_close((uv_handle_t*)front, on_front_close);
        free(buf->base);
        return;
    }

    if (nread > 0) {
        ssconn_t* conn = ssconn_get(front_fd);
        if (!conn) {
            _LOG_E("on_front_read ssconn_get conn error. front fd: %d", (int)front_fd);
            uv_close((uv_handle_t*)front, on_front_close);
            return;
        }
        on_front_read_ok(conn, buf->base, nread);

        // uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
        // if (!req) {
        //     _LOG_E("Failed to allocate memory for write request");
        //     free(buf->base);
        //     uv_close((uv_handle_t*)client, on_front_close);
        //     return;
        // }
        // uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
        // if (uv_write(req, client, &wrbuf, 1, echo_write) != 0) {
        //     _LOG_E("Failed to write to client");
        //     free(req);
        //     free(buf->base);
        //     uv_close((uv_handle_t*)client, on_front_close);
        // }
    }
    free(buf->base);
}

static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        _LOG_E("New connection error %s", uv_strerror(status));
        return;
    }

    uv_tcp_t* front = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    if (!front) {
        _LOG_E("Failed to allocate memory for front");
        return;
    }

    if (uv_tcp_init(server->loop, front) != 0) {
        _LOG_E("Failed to initialize front");
        free(front);
        return;
    }

    if (uv_accept(server, (uv_stream_t*)front) != 0) {
        _LOG_E("uv_accept error");
        uv_close((uv_handle_t*)front, on_front_close);
        return;
    }

    // uv_tcp_t* back = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    // if (!back) {
    //     _LOG_E("Failed to allocate memory for back");
    //     uv_close((uv_handle_t*)front, on_front_close);
    //     return;
    // }
    // if (uv_tcp_init(server->loop, &back) != 0) {
    //     _LOG_E("Failed to initialize back");
    //     uv_close((uv_handle_t*)front, on_front_close);
    //     free(back);
    //     return;
    // }
    // struct sockaddr_in dest_addr;
    // uv_ip4_addr("127.0.0.1", 7000, &dest_addr);
    // uv_connect_t connect_req;
    // uv_tcp_connect(&connect_req, &back, (const struct sockaddr*)&dest_addr, on_connect);

    uv_os_fd_t front_fd, server_fd;
    if (uv_fileno((const uv_handle_t*)front, &front_fd) != 0 || uv_fileno((const uv_handle_t*)server, &server_fd) != 0) {
        _LOG_E("Failed to get front fd");
        uv_close((uv_handle_t*)front, on_front_close);
        return;
    }
    _LOG("Accepted front fd: %d server fd: %d", (int)front_fd, (int)server_fd);

    ssconn_t* conn = ssconn_init((uv_stream_t*)front, SSCONN_TYPE_SERV, SSCONN_ST_WAIT);
    if (!conn) {
        _LOG_E("Failed to initialize ssconn. front fd: %d", (int)front_fd);
        uv_close((uv_handle_t*)front, on_front_close);
        return;
    }
    uv_read_start((uv_stream_t*)front, alloc_buffer, on_front_read);
}

// callback end

socks_t* socks_init(uv_loop_t* loop, ssconfig_t* conf) {
    socks_t* socks = (socks_t*)calloc(1, sizeof(socks_t));
    if (!socks) return NULL;
    socks->loop = loop;
    socks->conf = conf;
    loop->data = socks;
    return socks;
}

void socks_free(socks_t* socks) {
    if (!socks) return;
    if (socks->server) {
        uv_close((uv_handle_t*)socks->server, NULL);
        free(socks->server);
        socks->server = NULL;
    }
    free(socks);
    return;
}

int socks_start(socks_t* socks) {
    if (!socks) return _ERR;

    socks->server = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    if (!socks->server) return _ERR;

    if (uv_tcp_init(socks->loop, socks->server) != 0) {
        _LOG_E("Failed to initialize server");
        free(socks->server);
        socks->server = NULL;
        return _ERR;
    }

    struct sockaddr_in addr;
    if (uv_ip4_addr(socks->conf->listen_ip, socks->conf->listen_port, &addr) != 0) {
        _LOG_E("Invalid IP address or port");
        free(socks->server);
        socks->server = NULL;
        return _ERR;
    }

    if (uv_tcp_bind(socks->server, (const struct sockaddr*)&addr, 0) != 0) {
        _LOG_E("Failed to bind server");
        free(socks->server);
        socks->server = NULL;
        return _ERR;
    }

    int r = uv_listen((uv_stream_t*)socks->server, 128, on_new_connection);
    if (r) {
        _LOG_E("Listen error %s", uv_strerror(r));
        uv_close((uv_handle_t*)socks->server, NULL);
        free(socks->server);
        socks->server = NULL;
        return _ERR;
    }

    return _OK;
}

// void socks_stop(socks_t* socks) {
//     if (socks && socks->is_running) {
//         uv_close((uv_handle_t*)socks->server, NULL);
//         socks->is_running = 0;
//     }
// }
