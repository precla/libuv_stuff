/*
 * server using libuv
 * listens to clients on port 54545
 * and exchanges their messages
 * basically an irc server, but much simpler
 * connect to server using telnet
 */

#include "server.h"

uv_loop_t *loop;
struct sockaddr_in addr;
users userlist[MAX_USERS];
unsigned short usercount = 0;

int main(int argc, char *argv[]) {
    loop = uv_default_loop();
    assert(loop != NULL);

    uv_tcp_t st;
    uv_udp_t su;
    int listen;

    /*
     * 0 - TCP (defaults to TCP)
     * 1 - UDP
     */
    int usingProtocol = 0;

    if (argc > 1 && !strcmp(argv[1], "udp")) {
        fprintf(stdout, "using udp\n");
        usingProtocol = 1;
    }

    if (usingProtocol == 0) {
        assert(init_tcp_s(loop, &st) == 0);
        listen = uv_listen((uv_stream_t*)&st, MAX_CONNECTIONS, conn_tcp);
    } else if (usingProtocol == 1) {
        // TODO: listen error throws invalid argument atm for udp
        assert(uv_udp_init(loop, &su) == 0);
        listen = uv_listen((uv_stream_t*)&su, MAX_CONNECTIONS, conn_udp);
    }

    if (listen) {
        fprintf(stderr, "listen error: %s\n", uv_strerror(listen));
        return EXIT_FAILURE;
    }

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    return 0;
}

int init_tcp_s(uv_loop_t *loop, uv_tcp_t *s) {
    return uv_tcp_init(loop, s) | uv_ip4_addr("0.0.0.0", LISTEN_PORT, &addr) | uv_tcp_bind(s, (const struct sockaddr*)&addr, 0);
}

int init_udp_s(uv_loop_t* loop, uv_udp_t* s) {
    return uv_udp_init(loop, s) | uv_ip4_addr("0.0.0.0", LISTEN_PORT, &addr) | uv_udp_bind(s, (const struct sockaddr*)&addr, 0);
}

void conn_tcp(uv_stream_t* s, int status) {
    fprintf(stdout, "new tcp connection incoming...\n");
    if (status < 0) {
        fprintf(stderr, "error with setting up new connections %s\n", uv_strerror(status));
        return;
    }
    uv_tcp_t *connect = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    if (uv_tcp_init(loop, connect)) {
        fprintf(stderr ,"error with uv_tcp_init, within cb_conn_tcp\n");
        return;
    }
    if (uv_accept(s, (uv_stream_t*)connect) == 0) {
        uv_read_start((uv_stream_t*)connect, set_buffer, read_msg);
    }
}

void conn_udp(uv_stream_t* s, int status) {
    fprintf(stdout, "new udp connection incoming...\n");
    if (status < 0) {
        fprintf(stderr, "error with setting up new connections %s\n", uv_strerror(status));
        return;
    }
    uv_udp_t *connect = (uv_udp_t*)malloc(sizeof(uv_udp_t));
    if (uv_udp_init(loop, connect)) {
        fprintf(stderr ,"error with uv_udp_init, within cb_conn_udp\n");
        return;
    }
    if (uv_accept(s, (uv_stream_t*)connect) == 0) {
        uv_read_start((uv_stream_t*)connect, set_buffer, read_msg);
    }
}

void read_msg(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread > 0) {
        write_req_t *req = (write_req_t*)malloc(sizeof(write_req_t));
        req->buf = uv_buf_init(buf->base, nread);

        // check if user is setting nickname for chatroom
        char *nick = strstr(buf->base, "n: ");
        char *all = strstr(buf->base, "a: ");
        if (nick) {
            // move by 3 chars: 'n: '
            nick += 3;
            if (usercount < MAX_USERS) {
                // add nick to userlist[] if it doesn't already exist
                for (int i = 0; i < usercount; i++) {
                    // do not allow double nick usage
                    if (client == userlist[i].stream) {
                        fprintf(stdout, "user %s has already a nick\n", userlist[i].nick);
                        uv_buf_t response = uv_buf_init("    you already have a nick!\n", 28);
                        uv_write((uv_write_t*)req, client, &response, 1, msg_write);
                        return;
                    }

                    if (!strcmp(userlist[i].nick, nick)) {
                        fprintf(stdout, "%s - nick exists already, impostor?\n", nick);
                        uv_buf_t response = uv_buf_init("    nick exists already, try something else\n", 44);
                        uv_write((uv_write_t*)req, client, &response, 1, msg_write);
                        nick = NULL;
                    }
                }
                if (nick) {
                    strncpy(userlist[usercount].nick, nick, NICK_LENGTH);
                    userlist[usercount].stream = client;
                    fprintf(stdout, "new nick registered: %s", userlist[usercount].nick);
                    uv_buf_t response = uv_buf_init("    nick registered\n", 20);
                    uv_write((uv_write_t*)req, client, &response, 1, msg_write);
                    usercount++;
                }

            } else {
                fprintf(stdout, "user limit reached\n");
                uv_buf_t response = uv_buf_init("    user limit reached, come back later\n", 40);
                uv_write((uv_write_t*)req, client, &response, 1, msg_write);
            }

        } else if (all) {
            // send message to everyone, except the sender
            fprintf(stdout, "sending following message to everyone:\n%s", req->buf.base + 3);
            for (int i = 0; i < usercount; i++) {
                if (client != userlist[i].stream) {
                    uv_write((uv_write_t*)req, userlist[i].stream, &req->buf, 1, msg_write);
                    req->req.type = UV_UNKNOWN_REQ;
                }
            }

        } else {
            char destnick[NICK_LENGTH];
            int i = 0;

            strncpy(destnick, req->buf.base, (size_t)(strstr(req->buf.base, ":") - req->buf.base));

            for (i = 0; i < usercount; i++) {
                if (!strncmp(destnick, userlist[i].nick, strlen(destnick))) {
                    // if nick found, send msg to that user
                    uv_write((uv_write_t*)req, userlist[i].stream, &req->buf, 1, msg_write);
                    break;
                }
            }
            if (i >= usercount) {
                fprintf(stdout, "%s - nick does not exist\n", destnick);
                uv_buf_t response = uv_buf_init("    nick does not exist\n", 24);
                uv_write((uv_write_t*)req, client, &response, 1, msg_write);
            }
        }
        return;
    }

    if (nread < 0) {
        if (nread != UV_EOF)
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) client, on_close);
    }

    free(buf->base);
}

// stuff from libuv/docs/code/tcp-echo-server/main.c :
void set_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = (char*)malloc(size);
    buf->len = size;
}

void msg_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

void on_close(uv_handle_t* handle) {
    free(handle);
}

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t*) req;
    free(wr->buf.base);
    free(wr);
}
