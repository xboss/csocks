#ifndef _SOCKS5_H
#define _SOCKS5_H

#include "ss5.h"
#include "ssconn.h"

int ss5_auth(ssconn_t* conn, const char* buf, int len);
int ss5_auth_np(ssconn_t* conn, const char* buf, int len);
int ss5_data(ssconn_t* conn, const char* buf, int len, int tag_len);

#endif /* _SOCKS5_H */