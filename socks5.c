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
            phase =  SSCONN_PHASE_REQ;
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
    char ack[SS5_REQ_ACK_MAX_SZ];
    assert(SS5_REQ_ACK_MAX_SZ >= len);
    memcpy(ack, buf, len);
    char rep = 0x00;
    unsigned short port = 0;
    char ip[INET_ADDRSTRLEN];
    memset(ip, 0, INET_ADDRSTRLEN);
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
        assert(d_len <= SS5_DOMAIN_NAME_MAX_SZ);
        port = ntohs(*(uint16_t*)(buf + 4 + d_len + 1));
        uint64_t ctime = pconn_get_ctime(fd);
        assert(ctime > 0);
        domain_req_t* req = init_domain_req(fd, buf + 5, d_len, domain_cb, port, ctime, pipe);
        if (!req) {
            close_conn(fd);
            return;
        }
        int rt = resolve_domain(req);
        if (rt != 0) {
            close_conn(fd);
            return;
        }
        return;
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("socks5 ipv6 type");
        /* TODO: support ipv6 */
        return;
    } else {
        _LOG("socks5 request error atyp");
        return;
    }

    int cp_fd = connect_to(ip, port, fd);
    if (cp_fd <= 0) {
        close_conn(fd);
        return;
    }
    ack[1] = rep;
    int rt = send_to(fd, ack, len);
    if (rt == -1) {
        close_conn(fd);
        return;
    }
    _LOG("socks5 send_to ok fd:%d", fd);
    conn->phase = SSCONN_PHASE_DATA;
    return _OK;
}