#ifndef _POSIX_C_SOURCE
/* #define _POSIX_C_SOURCE 199506L */
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dns_resolver.h"
#include "pconn.h"
#include "ssev.h"
#include "sslog.h"
#include "ssnet.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

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

#define SS5_PHASE_AUTH 1
#define SS5_PHASE_REQ 2
#define SS5_PHASE_DATA 3
#define SS5_PHASE_AUTH_NP 4

/* 1 + 1 + 1 + 1 + 257 + 2 */
#define SS5_REQ_ACK_MAX_SZ 263
#define SS5_DOMAIN_NAME_MAX_SZ 256

struct socks_s {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    /*     int timeout;
        int read_buf_size; */
    char* log_file;
    int log_level;

    int server_fd;

    ssev_loop_t* loop;
    ssnet_t* net;
};
typedef struct socks_s socks_t;

static socks_t g_socks;

/* ---------------------------- */

static void handle_exit(int sig) {
    _LOG("exit by signal %d ... ", sig);
    ssev_stop(g_socks.loop);
}

static void signal_handler(int sn) {
    _LOG("signal_handler sig:%d", sn);
    switch (sn) {
        case SIGQUIT:
        case SIGINT:
        case SIGTERM:
            handle_exit(sn);
            break;
        default:
            break;
    }
}

#define _USAGE                                                                           \
    fprintf(stderr,                                                                      \
            "Usage: %s <listen ip> <listen port> [log level] [log file]\n \tlog level: " \
            "DEBUG|INFO|NOTICE|WARN|ERROR|FATAL\n ",                                     \
            argv[0])

static int parse_param(int argc, char const* argv[]) {
    if (argc < 3) {
        return _ERR;
    }
    int len = strnlen(argv[1], INET_ADDRSTRLEN + 1);
    if (len >= INET_ADDRSTRLEN + 1) {
        fprintf(stderr, "Invalid listen ip:%s\n", g_socks.listen_ip);
        return _ERR;
    }
    memcpy(g_socks.listen_ip, argv[1], len);
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid listen port:%u\n", port);
        return _ERR;
    }
    g_socks.listen_port = (unsigned short)port;
    g_socks.log_level = SSLOG_LEVEL_FATAL;
    if (argc >= 4) {
        len = 10;
        char* v = (char*)argv[3];
        if (strncasecmp(v, "DEBUG", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_DEBUG;
        } else if (strncasecmp(v, "INFO", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_INFO;
        } else if (strncasecmp(v, "NOTICE", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_NOTICE;
        } else if (strncasecmp(v, "WARN", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_WARN;
        } else if (strncasecmp(v, "ERROR", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_ERROR;
        } else if (strncasecmp(v, "FATAL", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_FATAL;
        } else {
            fprintf(stderr, "Invalid log level:%s, now default: FATAL\n", v);
        }
    }
    if (argc >= 5) {
        len = strnlen(argv[4], 256);
        char* v = (char*)argv[4];
        if (len >= 256) {
            fprintf(stderr, "Invalid log file:'%s'\n \tpathname max length is 255\n", v);
            return _ERR;
        }
        _ALLOC(g_socks.log_file, char*, len + 1);
        memset(g_socks.log_file, 0, len + 1);
        memcpy(g_socks.log_file, v, len);
    }
    return _OK;
}

static void close_conn(int fd) {
    if (fd <= 0) return;
    if (!pconn_is_exist(fd)) return;
    int cp_fd = pconn_get_couple_id(fd);

    /* TODO: debug */
    pconn_type_t type = pconn_get_type(fd);
    pconn_st_t st = pconn_get_status(fd);
    pconn_type_t cp_type = pconn_get_type(cp_fd);
    pconn_st_t cp_st = pconn_get_status(cp_fd);

    pconn_set_status(fd, PCONN_ST_OFF);
    ssnet_tcp_close(g_socks.net, fd);
    pconn_free(fd);
    _LOG("close_conn fd:%d type:%d st:%d", fd, type, st);
    if (cp_fd > 0) {
        pconn_set_status(cp_fd, PCONN_ST_OFF);
        ssnet_tcp_close(g_socks.net, cp_fd);
        pconn_free(cp_fd);
        _LOG("close_conn cp_fd:%d cp_type:%d cp_st:%d", cp_fd, cp_type, cp_st);
    }
}

static int flush_tcp_send(int fd, stream_buf_t* snd_buf, const char* buf, int len) {
    _LOG("flush_tcp_send fd:%d status:%d type:%d", fd, pconn_get_status(fd), pconn_get_type(fd));
    assert(pconn_get_status(fd) == PCONN_ST_ON);
    assert(snd_buf);
    assert(buf);
    assert(len > 0);
    int rt = ssnet_tcp_send(g_socks.net, fd, buf, len);
    if (rt == 0 || rt == -2) {
        _LOG("flush_tcp_send error fd:%d rt:%d len:%d", fd, rt, len);
        return _ERR;
    } else if (rt == -1) {
        /* pending */
        pconn_set_can_write(fd, 0);
        _LOG("flush_tcp_send pending send fd:%d len:%d", fd, len);
        sb_write(snd_buf, buf, len);
    } else if (rt < len) {
        /* remain */
        _LOG("flush_tcp_send remain send fd:%d len:%d", fd, rt);
        assert(rt > 0);
        sb_write(snd_buf, buf + rt, len - rt);
    }
    _LOG("flush_tcp_send ok. fd:%d", fd);
    return _OK;
}

static int connect_to(const char* ip, unsigned short port, int serv_fd) {
    if (port <= 0 || !ip || serv_fd <= 0) return _ERR;
    if (!pconn_is_exist(serv_fd)) {
        _LOG("connect_to serv_fd:%d does not exist", serv_fd);
        return _ERR;
    }
    if (pconn_get_couple_id(serv_fd) > 0) {
        _LOG("connect_to pconn_get_couple_id serv_fd:%d, error cli_id:%d", serv_fd, pconn_get_couple_id(serv_fd));
        return _ERR;
    }
    if (pconn_get_type(serv_fd) != PCONN_TYPE_SERV) {
        _LOG_E("connect_to serv_fd:%d does not server", serv_fd);
        return _ERR;
    }
    int fd = ssnet_tcp_connect(g_socks.net, ip, port);
    _LOG("connect_to fd:%d serv_fd:%d", fd, serv_fd);
    if (fd <= 0) {
        _LOG("connect_to fd:%d serv_fd:%d error", fd, serv_fd);
        return _ERR;
    }
    int rt;
    rt = pconn_init(fd, PCONN_TYPE_CLI, serv_fd, sb_init(NULL, 0), NULL);
    assert(rt == 0);
    /*     rt = pconn_set_status(serv_fd, PCONN_ST_ON);
        assert(rt == _OK); */
    rt = pconn_set_status(fd, PCONN_ST_READY);
    assert(rt == _OK);
    rt = pconn_add_cli_id(serv_fd, fd);
    assert(rt == 0);
    return fd;
}

static int send_to(int fd, const char* buf, int len) {
    if (fd <= 0 || !buf || len <= 0) return _ERR;
    pconn_st_t st = pconn_get_status(fd);
    if (st <= PCONN_ST_OFF) return _ERR;
    _LOG("send_to buf fd:%d len:%d", fd, len);
    stream_buf_t* snd_buf = pconn_get_snd_buf(fd);
    assert(snd_buf);
    int rt;
    if (pconn_get_status(fd) == PCONN_ST_READY) {
        rt = sb_write(snd_buf, buf, len);
        assert(rt == _OK);
        return rt;
    }
    int wlen = sb_get_size(snd_buf);
    if (wlen == 0 && pconn_can_write(fd)) return flush_tcp_send(fd, snd_buf, buf, len);
    rt = sb_write(snd_buf, buf, len);
    assert(rt == _OK);
    wlen = sb_get_size(snd_buf);
    assert(wlen > 0);
    if (pconn_can_write(fd)) {
        char* _ALLOC(wbuf, char*, wlen);
        memset(wbuf, 0, wlen);
        sb_read_all(snd_buf, wbuf, wlen);
        rt = flush_tcp_send(fd, snd_buf, wbuf, wlen);
        free(wbuf);
    }
    return rt;
}

static int send_to_cp(int fd, const char* buf, int len) {
    int cp_fd = pconn_get_couple_id(fd);
    if (cp_fd <= 0 || pconn_get_status(fd) <= PCONN_ST_OFF || pconn_get_status(cp_fd) <= PCONN_ST_OFF) {
        close_conn(fd);
        return _ERR;
    }
    int rt = send_to(cp_fd, buf, len);
    if (rt != _OK) close_conn(fd);
    return rt;
}

/* -------------- callback -------------- */

static void domain_cb(domain_req_t* req) {
    if (!req) {
        _LOG("req is NULL in domain_cb");
        return;
    }
    _LOG("dns id:%d resp:%d name:%s ip:%s", get_domain_req_id(req), get_domain_req_resp(req), get_domain_req_name(req), get_domain_req_ip(req));
    int src_fd = get_domain_req_id(req);
    if (src_fd > 0 && get_domain_req_resp(req) == 0) {
        int src_status = pconn_get_status(src_fd);
        if (src_status == 0) return;
        char* name = get_domain_req_name(req);
        int d_len = strlen(get_domain_req_name(req));
        assert(d_len > 0 && d_len < SS5_REQ_ACK_MAX_SZ);
        char* ip = get_domain_req_ip(req);
        unsigned short port = get_domain_req_port(req);
        char ack[SS5_REQ_ACK_MAX_SZ];
        memset(ack, 0, SS5_REQ_ACK_MAX_SZ);
        ack[0] = SS5_VER;
        ack[1] = SS5_REP_OK;
        ack[3] = SS5_ATYP_DOMAIN;
        ack[4] = d_len & 0xff;
        _LOG("domain_cb d_len:%d name:%s", d_len, name);
        memcpy(ack + 5, name, d_len);
        unsigned short nport = htons(port);
        /* ack[5 + d_len] = htons(port); */
        memcpy(ack + 5 + d_len, &nport, 2);

        uint64_t ctime = pconn_get_ctime(src_fd);
        if (ctime != get_domain_req_time(req)) {
            /* check if it is the fd that initiated the request.  */
            close_conn(src_fd);
            /* free_domain_req(req); */
            return;
        }

        int cp_fd = connect_to(ip, port, src_fd);
        if (cp_fd <= 0) {
            close_conn(src_fd);
            /* free_domain_req(req); */
            return;
        }
        int rt = send_to(src_fd, ack, 7 + d_len);
        if (rt == -1) {
            close_conn(src_fd);
            /* free_domain_req(req); */
            return;
        }
        _LOG("dns socks5 send_to ok fd:%d", src_fd);
        pconn_set_ex(src_fd, SS5_PHASE_DATA);
    } else {
        _LOG("dns domain_cb error fd:%d", src_fd);
        close_conn(src_fd);
    }
}

static void ss5_auth(int fd, const char* buf, int len) {
    if (buf[0] != SS5_VER || len < 3) {
        close_conn(fd);
        return;
    }
    int nmethods = (int)buf[1];
    if (nmethods > 6) {
        close_conn(fd);
        return;
    }
    char ack[2] = {SS5_VER, 0x00};
    int i, rt = 0, phase = 0;
    for (i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            /* NO AUTHENTICATION REQUIRED */
            phase = SS5_PHASE_REQ;
            break;
        } else if (buf[2 + i] == 0x02) {
            /* USERNAME/PASSWORD */
            ack[1] = 0x02;
            phase = SS5_PHASE_AUTH_NP;
            break;
        } else {
            /* No acceptable method */
            ack[1] = 0xff;
        }
    }
    rt = send_to(fd, ack, sizeof(ack));
    if (rt == -1) {
        close_conn(fd);
        return;
    }
    pconn_set_ex(fd, phase);
}

static void ss5_auth_np(int fd, const char* buf, int len) {
    if (buf[0] != SS5_AUTH_NP_VER || len < 5) {
        close_conn(fd);
        return;
    }
    int name_len = buf[1];
    if (name_len <= 0) {
        close_conn(fd);
        return;
    }
    int pwd_len = buf[2 + name_len];
    if (pwd_len < 0) {
        close_conn(fd);
        return;
    }

    int auth_rt = 0;
    /* TODO: check name and password */

    char ack[2] = {SS5_AUTH_NP_VER, 0x00};
    if (auth_rt != 0) {
        ack[1] = 0x01;
    }
    int rt = send_to(fd, ack, sizeof(ack));
    if (rt == -1) {
        close_conn(fd);
        return;
    }
    pconn_set_ex(fd, SS5_PHASE_REQ);
}

static void ss5_req(int fd, const char* buf, int len) {
    if (buf[0] != SS5_VER || len < 7) {
        close_conn(fd);
        return;
    }
    unsigned char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        /* TODO: support bind and udp associate */
        _LOG("socks5: now only 'connect' command is supported.");
    }
    if (cmd != SS5_CMD_CONNECT) {
        close_conn(fd);
        return;
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
    pconn_set_ex(fd, SS5_PHASE_DATA);
}

static int on_cli_recv(int fd, const char* buf, int len) {
    return send_to_cp(fd, buf, len);
}

static int on_serv_recv(int fd, const char* buf, int len) {
    int phase = pconn_get_ex(fd);
    assert(phase != 0);
    int rt = _OK;
    if (phase == SS5_PHASE_AUTH) {
        ss5_auth(fd, buf, len);
    } else if (phase == SS5_PHASE_REQ) {
        ss5_req(fd, buf, len);
    } else if (phase == SS5_PHASE_AUTH_NP) {
        ss5_auth_np(fd, buf, len);
    } else if (phase == SS5_PHASE_DATA) {
        rt = send_to_cp(fd, buf, len);
    } else {
        _LOG_E("socks5 phase error %d", phase);
        close_conn(fd);
        return _ERR;
    }
    return rt;
}

static int on_recv(ssnet_t* net, int fd, const char* buf, int len, struct sockaddr* addr) {
    int conn_type = pconn_get_type(fd);
    if (conn_type == PCONN_TYPE_SERV) {
        return on_serv_recv(fd, buf, len);
    } else if (conn_type == PCONN_TYPE_CLI) {
        return on_cli_recv(fd, buf, len);
    } else {
        _LOG_E("connection type error");
        return _ERR;
    }
    return _OK;
}

static int on_close(ssnet_t* net, int fd) {
    _LOG("on close fd:%d", fd);
    close_conn(fd);
    return _OK;
}

static int on_accept(ssnet_t* net, int fd) {
    int rt = pconn_init(fd, PCONN_TYPE_SERV, 0, sb_init(NULL, 0), NULL);
    assert(rt == _OK);
    rt = pconn_set_status(fd, PCONN_ST_ON);
    assert(rt == _OK);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    pconn_set_ex(fd, SS5_PHASE_AUTH);
    pconn_set_is_secret(fd, 0);
    return _OK;
}

static int on_connected(ssnet_t* net, int fd) {
    _LOG("on_connected fd:%d", fd);
    if (!pconn_is_exist(fd)) {
        _LOG_E("on_connected fd:%d does not exist, close", fd);
        ssnet_tcp_close(net, fd);
        return _ERR;
    }
    if (pconn_get_status(fd) == PCONN_ST_OFF) {
        _LOG("on_connected fd:%d is off, close", fd);
        close_conn(fd);
        return _ERR;
    }
    int cp_fd = pconn_get_couple_id(fd);
    if (cp_fd <= 0) {
        _LOG("on_connected fd:%d couple does not exist", fd);
        close_conn(fd);
        return _ERR;
    }
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_SERV);
    int rt = pconn_set_status(fd, PCONN_ST_ON);
    assert(rt == _OK);
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(ssnet_t* net, int fd) {
    _LOG("on_writable fd:%d", fd);
    assert(pconn_get_type(fd) != PCONN_TYPE_NONE);
    int rt = _OK;
    if (pconn_get_status(fd) == PCONN_ST_READY && pconn_get_type(fd) == PCONN_TYPE_CLI) {
        rt = on_connected(net, fd);
    }

    if (rt == _OK) {
        rt = pconn_set_can_write(fd, 1);
        assert(rt == 0);
        if (pconn_get_status(fd) == PCONN_ST_ON) {
            stream_buf_t* snd_buf = pconn_get_snd_buf(fd);
            assert(snd_buf);
            int len = sb_get_size(snd_buf);
            if (len > 0) {
                char* _ALLOC(buf, char*, len);
                sb_read_all(snd_buf, buf, len);
                rt = flush_tcp_send(fd, snd_buf, buf, len);
                free(buf);
                if (rt != _OK) {
                    close_conn(fd);
                }
            }
        }
    }
    return rt;
}

static void free_close_cb(int id, void* u) {
    ssnet_t* net = (ssnet_t*)u;
    assert(net);
    ssnet_tcp_close(net, id);
}

/* ---------------------------- */

int main(int argc, char const* argv[]) {
    memset(&g_socks, 0, sizeof(socks_t));

    if (parse_param(argc, argv) != _OK) {
        _USAGE;
        return 1;
    }

    sslog_init(g_socks.log_file, g_socks.log_level);
    printf("listen ip: %s \nlisten port: %u \nlog level: %d \nlog file: %s\n", g_socks.listen_ip, g_socks.listen_port, g_socks.log_level, g_socks.log_file);
    if (g_socks.log_file) free(g_socks.log_file);

    g_socks.loop = ssev_init();
    if (!g_socks.loop) {
        _LOG_E("init loop error.");
        return 1;
    }
    /* ssev_set_ev_timeout(g_socks.loop, g_socks.timeout); */

    if (init_domain_resolver(g_socks.loop) != 0) {
        _LOG_E("init domain resolver error.");
        return 1;
    }

    g_socks.net = ssnet_init(g_socks.loop, 0);
    if (!g_socks.net) {
        ssev_free(g_socks.loop);
        return 1;
    }
    ssnet_set_userdata(g_socks.net, pipe);
    ssnet_set_recv_cb(g_socks.net, on_recv);
    ssnet_set_close_cb(g_socks.net, on_close);
    ssnet_set_writable_cb(g_socks.net, on_writable);
    g_socks.server_fd = ssnet_tcp_init_server(g_socks.net, g_socks.listen_ip, g_socks.listen_port, on_accept);
    if (g_socks.server_fd <= 0) {
        _LOG_E("init ssnet error.");
        ssnet_free(g_socks.net);
        ssev_free(g_socks.loop);
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signal_handler;
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    ssev_run(g_socks.loop);
    pconn_free_all(g_socks.net, free_close_cb);
    ssnet_free(g_socks.net);
    free_domain_resolver(g_socks.loop);
    ssev_free(g_socks.loop);

    _LOG("Bye");
    sslog_free();
    return 0;
}