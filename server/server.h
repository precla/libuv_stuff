#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#define LISTEN_PORT         54545
#define MAX_CONNECTIONS     14
#define MAX_USERS           12
#define NICK_LENGTH         16

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    char nick[NICK_LENGTH];
    uv_stream_t *stream;
} users;

int init_tcp_s(uv_loop_t *loop, uv_tcp_t *s);
int init_udp_s(uv_loop_t *loop, uv_udp_t *s);
void conn_tcp(uv_stream_t *s, int status);
void conn_udp(uv_stream_t *s, int status);
void read_msg(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
void set_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void msg_write(uv_write_t *req, int status);
void on_close(uv_handle_t* handle);
void free_write_req(uv_write_t *req);
