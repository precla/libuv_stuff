#pragma once

#include <assert.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#define LISTEN_PORT         54545
#define MAX_CONNECTIONS     14
#define MAX_USERS           12
#define NICK_LENGTH         16

enum send_to {
    NICKREG,
    ALL,
    ALL_DELAY,
    NICK,
};

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    char nick[NICK_LENGTH+2];   // +2 for "\r\n"
    uv_stream_t *stream;
    uv_buf_t buf;
} user;

int init_tcp_s(uv_loop_t *loop, uv_tcp_t *s);
void conn_tcp(uv_stream_t *s, int status);
void read_msg(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
void message_all(uv_timer_t *handle);
void prepare_message(uv_stream_t *s, uv_buf_t *msg);
void send_message();
void send_message_no_prep(write_req_t *wrt_l, uv_stream_t *s, uv_buf_t *msg);
void set_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void msg_write(uv_write_t *req, int status);
void signal_handler(uv_signal_t *handle, int signum);
void on_close(uv_handle_t* handle);
void free_write_req(uv_write_t *req);
void freeall();
