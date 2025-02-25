#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssconf.h"

#include "socks5server.h"

static ssconfig_t g_conf;
static socks_t* socks = NULL;

static int load_conf(const char* conf_file, ssconfig_t* conf) {
    char* keys[] = {"listen_ip", "listen_port", "password", "timeout", "read_buf_size", "log_file", "log_level"};
    int keys_cnt = sizeof(keys) / sizeof(char*);
    ssconf_t* cf = ssconf_init(keys, keys_cnt);
    assert(cf);
    int rt = ssconf_load(cf, conf_file);
    if (rt != 0) return -1;
    conf->log_level = SSLOG_LEVEL_ERROR;
    char* v = NULL;
    int i;
    for (i = 0; i < keys_cnt; i++) {
        v = ssconf_get_value(cf, keys[i]);
        if (!v) {
            printf("'%s' does not exists in config file '%s'.\n", keys[i], conf_file);
            continue;
        }
        int len = strlen(v);
        if (strcmp("listen_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->listen_ip, v, len);
            }
        } else if (strcmp("listen_port", keys[i]) == 0) {
            conf->listen_port = (unsigned short)atoi(v);
        } else if (strcmp("password", keys[i]) == 0) {
            pwd2key(conf->key, CIPHER_KEY_LEN, v, strlen(v));
        } else if (strcmp("timeout", keys[i]) == 0) {
            conf->timeout = atoi(v);
        } else if (strcmp("read_buf_size", keys[i]) == 0) {
            conf->read_buf_size = atoi(v);
        } else if (strcmp("log_file", keys[i]) == 0) {
            conf->log_file = (char*)calloc(1, len + 1);
            if (!conf->log_file) {
                ssconf_free(cf);
                return -1;
            }
            memcpy(conf->log_file, v, len);
        } else if (strcmp("log_level", keys[i]) == 0) {
            if (strcmp(v, "DEBUG") == 0) {
                conf->log_level = SSLOG_LEVEL_DEBUG;
            } else if (strcmp(v, "INFO") == 0) {
                conf->log_level = SSLOG_LEVEL_INFO;
            } else if (strcmp(v, "NOTICE") == 0) {
                conf->log_level = SSLOG_LEVEL_NOTICE;
            } else if (strcmp(v, "WARN") == 0) {
                conf->log_level = SSLOG_LEVEL_WARN;
            } else if (strcmp(v, "ERROR") == 0) {
                conf->log_level = SSLOG_LEVEL_ERROR;
            } else {
                conf->log_level = SSLOG_LEVEL_FATAL;
            }
        }
        printf("%s : %s\n", keys[i], v);
    }
    ssconf_free(cf);
    printf("------------\n");
    return 0;
}

static int check_config(ssconfig_t* conf) {
    if (conf->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port:%u in configfile.\n", conf->listen_port);
        return -1;
    }
    return 0;
}

static void on_sigpipe(uv_signal_t* handle, int signum) {
    _LOG("Caught signal %d: SIGPIPE", signum);
}

static void on_sigint(uv_signal_t* handle, int signum) {
    _LOG("Caught signal %d: SIGINT, shutting down...", signum);
    uv_stop(handle->loop);
}

int main(int argc, char const* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }
    memset(&g_conf, 0, sizeof(ssconfig_t));
    int rt = load_conf(argv[1], &g_conf);
    if (rt != 0) return 1;
    if (check_config(&g_conf) != 0) return 1;
    sslog_init(g_conf.log_file, g_conf.log_level);
    if (g_conf.log_file) free(g_conf.log_file);

    uv_loop_t* loop = uv_default_loop();

    uv_signal_t sigpipe;
    if (uv_signal_init(loop, &sigpipe) < 0 || uv_signal_start(&sigpipe, on_sigpipe, SIGPIPE) < 0) {
        _LOG_E("Failed to set up SIGPIPE handler");
        return 1;
    }

    uv_signal_t sigint;
    if (uv_signal_init(loop, &sigint) < 0 || uv_signal_start(&sigint, on_sigint, SIGINT) < 0) {
        _LOG_E("Failed to set up SIGINT handler");
        return 1;
    }

    socks = socks_init(loop, &g_conf);
    if (!socks) {
        _LOG_E("Failed to initialize socks5 server.");
        return 1;
    }

    rt = socks_start(socks);
    if (rt != 0) {
        _LOG_E("Failed to start socks5 server.");
        socks_free(socks);
        return 1;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    socks_free(socks);
    sslog_free();
    printf("Bye\n");
    return 0;
}
