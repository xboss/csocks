#ifndef _SS5_H
#define _SS5_H

#include <uv.h>
#include <assert.h>

#include "cipher.h"
#include "sslog.h"

#define _OK 0
#define _ERR -1

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

typedef struct {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    char key[CIPHER_KEY_LEN + 1];
    int timeout;
    int read_buf_size;
    char* log_file;
    int log_level;
} ssconfig_t;


#endif /* _SS5_H */