#include "socks5.h"

#define SS5_VER 0x05U
#define SS5_AUTH_NP_VER 0x01U
#define SS5_CMD_CONNECT 0x01U
#define SS5_CMD_BIND 0x02U
#define SS5_CMD_UDP_ASSOCIATE 0x03U

#define SS5_ATYP_IPV4 0x01U
#define SS5_ATYP_DOMAIN 0x03U
#define SS5_ATYP_IPV6 0x04U

/*
REP: 回复请求的状态
0x00 成功代理
0x01 SOCKS服务器出现了错误
0x02 不允许的连接
0x03 找不到网络
0x04 找不到主机
0x05 连接被拒
0x06 TTL超时
0x07 不支持的CMD
0x08 不支持的ATYP
 */
#define SS5_REP_OK 0x00U
#define SS5_REP_ERR 0x01U
#define SS5_REP_HOST_ERR 0x04U

int ss5_auth_np(ssconn_t* conn, const char* buf, int len) {
    if (buf[0] != SS5_AUTH_NP_VER || len < 5) {
        _LOG_E("ss5_auth_np version error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    int name_len = buf[1];
    if (name_len <= 0) {
        _LOG_E("ss5_auth_np name_len error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    int pwd_len = buf[2 + name_len];
    if (pwd_len < 0) {
        _LOG_E("ss5_auth_np pwd_len error");
        ssconn_close(conn->fd);
        return _ERR;
    }

    int auth_rt = 0;
    /* TODO: check name and password */

    char ack[2] = {SS5_AUTH_NP_VER, 0x00};
    if (auth_rt != 0) {
        ack[1] = 0x01;
    }

    int rt = ssbuffer_grow(conn->send_buf, sizeof(ack));
    if (rt != _OK) {
        _LOG_E("ss5_auth_np ssbuffer_grow send_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->send_buf->buf + conn->send_buf->len, ack, sizeof(ack));
    conn->send_buf->len += sizeof(ack);

    rt = ssconn_flush_send_buf(conn);
    if (rt != _OK) {
        _LOG_E("ss5_auth_np ssconn_flush_send_buf error");
        return _ERR;
    }

    conn->phase = SSCONN_PHASE_REQ;
    return _OK;
}

int ss5_auth(ssconn_t* conn, const char* buf, int len) {
    if (buf[0] != SS5_VER || len < 3) {
        _LOG_E("ss5_auth version error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    int nmethods = (int)buf[1];
    if (nmethods > 6) {
        _LOG_E("ss5_auth nmethods error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    char ack[2] = {SS5_VER, 0x00};
    int i, rt = 0, phase = SSCONN_PHASE_NONE;
    for (i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            /* NO AUTHENTICATION REQUIRED */
            phase = SSCONN_PHASE_REQ;
            break;
        } else if (buf[2 + i] == 0x02) {
            /* USERNAME/PASSWORD */
            ack[1] = 0x02;
            phase = SSCONN_PHASE_AUTH_NP;
            break;
        } else {
            /* No acceptable method */
            ack[1] = 0xff;
        }
    }

    rt = ssbuffer_grow(conn->send_buf, sizeof(ack));
    if (rt != _OK) {
        _LOG_E("ss5_auth ssbuffer_grow send_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->send_buf->buf + conn->send_buf->len, ack, sizeof(ack));
    conn->send_buf->len += sizeof(ack);

    rt = ssconn_flush_send_buf(conn);
    if (rt != _OK) {
        _LOG_E("ss5_auth ssconn_flush_send_buf error");
        return _ERR;
    }

    conn->phase = phase;
    return _OK;
}

int ss5_data(ssconn_t* conn, const char* buf, int len, int tag_len) {
    ssconn_t* cp_conn = ssconn_get(conn->cp_fd);
    if (!cp_conn) {
        _LOG_E("ss5_data ssconn_get cp_conn error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    assert(cp_conn->cp_fd > 0);
    assert(conn->fd == cp_conn->cp_fd && cp_conn->fd == conn->cp_fd);
    assert(cp_conn->recv_buf);
    assert(cp_conn->send_buf);
    if (cp_conn->status == SSCONN_ST_OFF) {
        _LOG_W("ss5_data cp_conn is closed. fd:%d", cp_conn->fd);
        ssconn_close(cp_conn->cp_fd);
        return _ERR;
    }
    // send to buffer
    int rt = ssbuffer_grow(cp_conn->send_buf, len - tag_len);
    if (rt != _OK) {
        _LOG_E("ss5_data ssbuffer_grow send_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, buf, len - tag_len);
    cp_conn->send_buf->len += len - tag_len;

    memmove(conn->recv_buf->buf, conn->recv_buf->buf + PACKET_HEAD_LEN + len, conn->recv_buf->len - PACKET_HEAD_LEN - len);
    conn->recv_buf->len -= PACKET_HEAD_LEN + len;
    assert(conn->recv_buf->len >= 0);

    rt = ssconn_flush_send_buf(cp_conn);
    if (rt != _OK) {
        _LOG_E("ss5_data ssconn_flush_send_buf error");
        return _ERR;
    }
    return _OK;
}

static void on_back_connect(uv_connect_t* connect_req, int status) {
    ssconn_t* conn = (ssconn_t*)connect_req->data;
    assert(conn);
    assert(conn->fd > 0);
    assert(conn->status == SSCONN_ST_WAIT);
    assert(conn->phase == SSCONN_PHASE_REQ);
    assert(conn->type == SSCONN_TYPE_SERV);
    assert(conn->tcp);
    assert(conn->tcp->loop);

    if (status == -1) {
        _LOG_E("back connect error: %s", uv_strerror(status));
        ssconn_close(conn->fd);
        free(connect_req);
        free(connect_req->handle);
        return;
    }

    uv_os_fd_t back_fd;
    if (uv_fileno((const uv_handle_t*)conn->tcp, &back_fd) != 0) {
        _LOG_E("Failed to get back fd");
        ssconn_close(conn->fd);
        free(connect_req);
        free(connect_req->handle);
        return;
    }
    _LOG("back connect ok. front_fd: %d back_fd: %d", conn->fd, (int)back_fd);

    ssconn_t* cp_conn = ssconn_init(connect_req->handle, SSCONN_TYPE_CLI, SSCONN_ST_WAIT);
    if (!cp_conn) {
        _LOG_E("Failed to initialize ssconn. back fd: %d", (int)back_fd);
        ssconn_close(conn->fd);
        free(connect_req);
        free(connect_req->handle);
        return;
    }
    cp_conn->tcp = connect_req->handle;
    conn->cp_fd = cp_conn->fd;
    cp_conn->cp_fd = conn->fd;
    conn->status = SSCONN_ST_ON;
    cp_conn->status = SSCONN_ST_ON;
    int rt = ssconn_flush_send_buf(conn);
    if (rt != _OK) {
        _LOG_E("on_back_connect ssconn_flush_send_buf error front_fd: %d", conn->fd);
        free(connect_req);
        free(connect_req->handle);
        ssconn_close(conn->fd);
        return;
    }
    free(connect_req);
    conn->phase = SSCONN_PHASE_DATA;
}

static uv_tcp_t* tcp_connect(uv_loop_t* loop, const char* ip, unsigned short port, uv_connect_cb cb, ssconn_t* conn) {
    assert(loop);
    assert(ip);
    assert(port > 0);
    assert(cb);

    uv_tcp_t* tcp = (uv_tcp_t*)calloc(1, sizeof(uv_tcp_t));
    if (!tcp) {
        _LOG_E("Failed to allocate memory for tcp_connect");
        return NULL;
    }
    int rt = uv_tcp_init(loop, tcp);
    if (rt != 0) {
        _LOG_E("Failed to initialize tcp");
        free(tcp);
        return NULL;
    }
    struct sockaddr_in dest_addr;
    rt = uv_ip4_addr(ip, port, &dest_addr);
    if (rt != 0) {
        _LOG_E("Invalid IP address or port");
        free(tcp);
        return NULL;
    }
    uv_connect_t* connect_req = (uv_connect_t*)calloc(1, sizeof(uv_connect_t));
    connect_req->data = conn;

    rt = uv_tcp_connect(connect_req, tcp, (const struct sockaddr*)&dest_addr, cb);
    if (rt != 0) {
        _LOG_E("Failed to connect to back");
        free(tcp);
        free(connect_req);
        return NULL;
    }
    return tcp;
}

void on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    _LOG("on_resolved status %d", status);
    if (status < 0) {
        _LOG_E("Failed to resolve domain %s", uv_strerror(status));
        free(req);
        return;
    }

    ssconn_t* conn = (ssconn_t*)req->data;
    assert(conn);
    assert(conn->fd > 0);
    assert(conn->status == SSCONN_ST_WAIT);
    assert(conn->phase == SSCONN_PHASE_REQ);
    assert(conn->type == SSCONN_TYPE_SERV);
    assert(conn->tcp);
    assert(conn->tcp->loop);
    assert(conn->ex_data > 0);

    if (!res && !res->ai_addr) {
        _LOG_E("Failed to resolve domain");
        ssconn_close(conn->fd);
        free(req);
        return;
    }

    struct sockaddr* addr = res->ai_addr;

    char ip_str[INET_ADDRSTRLEN] = {0};
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        uv_ip4_name(addr_in, ip_str, sizeof(ip_str));
        _LOG("Resolved IPv4 address: %s\n", ip_str);
        unsigned short port = conn->ex_data;
        uv_tcp_t* back = tcp_connect(conn->tcp->loop, ip_str, port, on_back_connect, conn);
        if (!back) {
            _LOG_E("Failed to connect to back");
            ssconn_close(conn->fd);
            return;
        }
    } else if (addr->sa_family == AF_INET6) {
        // struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
        // char ip_str[INET6_ADDRSTRLEN];
        // uv_ip6_name(addr_in6, ip_str, sizeof(ip_str));
        _LOG_W("unsupported IPv6 dns");
    } else {
        _LOG_E("Unknown address family\n");
    }
    free(req);
    _LOG("on_resolved end");
}

int resolve_domain(ssconn_t* conn, char* domain, int family) {
    assert(conn);
    assert(conn->fd > 0);
    assert(conn->status == SSCONN_ST_WAIT);
    assert(conn->phase == SSCONN_PHASE_REQ);
    assert(conn->type == SSCONN_TYPE_SERV);
    assert(conn->tcp);
    assert(conn->tcp->loop);
    assert(conn->ex_data > 0);
    assert(domain);
    assert(family == AF_INET || family == AF_INET6);
    _LOG("resolve_domain %d", conn->fd);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    uv_getaddrinfo_t* getaddrinfo_req = (uv_getaddrinfo_t*)calloc(1, sizeof(uv_getaddrinfo_t));
    if (!getaddrinfo_req) {
        _LOG_E("Failed to allocate memory for getaddrinfo_req");
        ssconn_close(conn->fd);
        return _ERR;
    }
    getaddrinfo_req->data = conn;
    int rt = uv_getaddrinfo(conn->tcp->loop, (uv_getaddrinfo_t*)getaddrinfo_req, on_resolved, domain, NULL, &hints);
    if (rt != 0) {
        _LOG_E("Failed to resolve domain %s", uv_strerror(rt));
        free(getaddrinfo_req);
        ssconn_close(conn->fd);
        return _ERR;
    }
    return _OK;
}

int ss5_req(ssconn_t* conn, const char* buf, int len) {
    if (buf[0] != SS5_VER || len < 7) {
        _LOG_E("ss5_req version error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    unsigned char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        /* TODO: support bind and udp associate */
        _LOG("socks5: now only 'connect' command is supported.");
    }
    if (cmd != SS5_CMD_CONNECT) {
        _LOG_E("ss5_req cmd not connect error");
        ssconn_close(conn->fd);
        return _ERR;
    }

    int rt = ssbuffer_grow(conn->send_buf, len);
    if (rt != _OK) {
        _LOG_E("ss5_req ssbuffer_grow ack error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->send_buf, buf, len);
    conn->send_buf->len += len;

    char domain[256] = {0}; /* TODO: */
    // char ack[SS5_REQ_ACK_MAX_SZ];
    // assert(SS5_REQ_ACK_MAX_SZ >= len);
    // memcpy(ack, buf, len);
    unsigned short port = 0;
    char ip[INET_ADDRSTRLEN] = {0};
    unsigned char atyp = buf[3];
    if (atyp == SS5_ATYP_IPV4) {
        struct in_addr addr;
        addr.s_addr = *(uint32_t*)(buf + 4);
        char* ipp = inet_ntoa(addr);
        memcpy(ip, ipp, strlen(ipp));
        port = ntohs(*(uint16_t*)(buf + 8));
        _LOG("socks5 ip:%s:%u", ip, port);
    } else if (atyp == SS5_ATYP_DOMAIN) {
        int d_len = (int)(buf[4] & 0xff);
        assert(d_len > 0 && d_len < 256);
        memcpy(domain, buf + 5, d_len);
        _LOG("socks5 domain:%s", domain);
        port = ntohs(*(uint16_t*)(buf + 4 + d_len + 1));
        conn->ex_data = port;
        rt = resolve_domain(conn, domain, AF_INET);
        if (rt != 0) {
            ssconn_close(conn->fd);
            return _ERR;
        }
        return _OK;
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("socks5 ipv6 type");
        /* TODO: support ipv6 */
        return _ERR;
    } else {
        _LOG("socks5 request error atyp");
        ssconn_close(conn->fd);
        return _ERR;
    }

    uv_tcp_t* back = tcp_connect(conn->tcp->loop, ip, port, on_back_connect, conn);
    if (!back) {
        _LOG_E("Failed to connect to back");
        ssconn_close(conn->fd);
        return _ERR;
    }
    return _OK;
}

///////////////////////////////////////

static char packet_tag[] = {'S', 'S', 'P'};

///////////////////////////////////////
// tcp server callback start
///////////////////////////////////////

void on_close(uv_handle_t* tcp) {
    /* TODO: */
    return;
}

int on_accept(uv_stream_t* tcp) {
    ssconn_t* conn = ssconn_init((uv_stream_t*)tcp, SSCONN_TYPE_SERV, SSCONN_ST_WAIT);
    if (!conn) {
        _LOG_E("Failed to initialize ssconn.");
        uv_close((uv_handle_t*)tcp, NULL);  // 在没有创建conn之前不用回调
        return _ERR;
    }
    return _OK;
}

#define RET_PHASE_ERROR(_msg) \
    do {                      \
        if (rt != _OK) {      \
            _LOG_E(_msg);     \
            free(plain_text); \
            return _ERR;      \
        }                     \
    } while (0)

int on_front_read(uv_stream_t* tcp, const char* buf, int len) {
    uv_os_fd_t fd;
    if (uv_fileno((const uv_handle_t*)tcp, &fd) != 0) {
        _LOG_E("on_front_read get fd error");
        uv_close((uv_handle_t*)tcp, on_close);
        return _ERR;
    }

    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG_E("on_front_read ssconn_get conn error. front fd: %d", (int)fd);
        uv_close((uv_handle_t*)tcp, on_close);
        return _ERR;
    }

    // check conn
    assert(conn);
    if (conn->status == SSCONN_ST_OFF) {
        _LOG_E("on_front_read conn off");
        ssconn_close(conn->fd);
        return _ERR;
    }

    assert(conn->recv_buf);
    assert(conn->send_buf);

    socks5_t* socks5 = (socks5_t*)conn->tcp->loop->data;
    assert(socks5);

    int rt = ssbuffer_grow(conn->recv_buf, len);
    if (rt != _OK) {
        _LOG_E("on_front_read ssbuffer_grow recv_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->recv_buf->buf + conn->recv_buf->len, buf, len);
    conn->recv_buf->len += len;
    assert(conn->recv_buf->len > 0);

    int ciphertext_len = 0;
    int plain_text_len = 0;
    char* plain_text = NULL;
    while (conn->recv_buf->len > PACKET_HEAD_LEN) {
        // unpack
        ciphertext_len = ntohl(*(int*)conn->recv_buf->buf);
        if (ciphertext_len <= 0 || ciphertext_len > 65535) { /* TODO: magic number */
            _LOG_E("on_front_read ciphertext_len:%d error. recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
            ssconn_close(conn->fd);
            return _ERR;
        }
        if (ciphertext_len > conn->recv_buf->len - PACKET_HEAD_LEN) {
            _LOG("on_front_read ciphertext_len:%d > recv_buf->len:%d rfd:%d sfd:%d", ciphertext_len, conn->recv_buf->len, conn->fd, conn->cp_fd);
            return _OK;
        }
        // decrypt
        plain_text = aes_decrypt(socks5->conf->key, conn->recv_buf->buf + PACKET_HEAD_LEN, ciphertext_len, &plain_text_len);
        if (plain_text == NULL) {
            _LOG_E("on_front_read aes_decrypt error");
            ssconn_close(conn->fd);
            return _ERR;
        }

        assert(plain_text_len > sizeof(packet_tag));

        // check packet tag
        if (memcmp(plain_text + plain_text_len - sizeof(packet_tag), packet_tag, sizeof(packet_tag)) != 0) {
            _LOG_E("on_front_read packet_tag error");
            ssconn_close(conn->fd);
            free(plain_text);
            return _ERR;
        }

        if (conn->phase == SSCONN_PHASE_AUTH) {
            rt = ss5_auth(conn, plain_text, plain_text_len - sizeof(packet_tag));
            RET_PHASE_ERROR("on_front_read ss5_auth error");
        } else if (conn->phase == SSCONN_PHASE_AUTH_NP) {
            rt = ss5_auth_np(conn, plain_text, plain_text_len - sizeof(packet_tag));
            RET_PHASE_ERROR("on_front_read ss5_auth_np error");
        } else if (conn->phase == SSCONN_PHASE_REQ) {
            rt = ss5_req(conn, plain_text, plain_text_len - sizeof(packet_tag));
            RET_PHASE_ERROR("on_front_read ss5_req error");
        } else if (conn->phase == SSCONN_PHASE_DATA) {
            assert(conn->cp_fd > 0);
            assert(conn->status == SSCONN_ST_ON);
            rt = ss5_data(conn, plain_text, plain_text_len, sizeof(packet_tag));
            RET_PHASE_ERROR("on_front_read ss5_data error");
        }
        free(plain_text);
    }
    return _OK;
}

///////////////////////////////////////
// tcp server callback end
///////////////////////////////////////

socks5_t* socks5_init(uv_loop_t* loop, ssconfig_t* conf) {
    if (!loop || !conf) return NULL;
    socks5_t* socks5 = (socks5_t*)calloc(1, sizeof(socks5_t));
    if (!socks5) return NULL;
    socks5->loop = loop;
    socks5->conf = conf;
    loop->data = socks5;
    socks5->tcp_server = tcp_server_init(loop, conf->listen_ip, conf->listen_port, conf->read_buf_size);
    if (!socks5->tcp_server) {
        _LOG_E("Failed to initialize tcp server");
        free(socks5);
        return NULL;
    }
    socks5->tcp_server->on_accept = on_accept;
    socks5->tcp_server->on_read = on_front_read;
    socks5->tcp_server->on_close = on_close;
    return socks5;
}

void socks5_free(socks5_t* socks5) {
    if (!socks5) return;
    if (socks5->tcp_server) {
        tcp_server_free(socks5->tcp_server);
        socks5->tcp_server = NULL;
    }
    free(socks5);
    return;
}

int socks5_start(socks5_t* socks5) {
    if (!socks5) return _ERR;
    int rt = tcp_server_start(socks5->tcp_server);
    if (rt != _OK) {
        _LOG_E("Failed to start tcp server");
        return _ERR;
    }
    return _OK;
}
