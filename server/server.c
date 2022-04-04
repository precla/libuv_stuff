/*
 * server using libuv
 * listens to clients on port 54545, tcp
 * and exchanges their messages
 * basically an irc server, but much simpler
 * connect to server using telnet
 */

#include "server.h"

uv_loop_t *loop;
uv_timer_t timer;

write_req_t *wrt;
uv_stream_t *uvstrm;
uv_tcp_t *tcpconn[MAX_USERS];
uv_buf_t *bufmsg;

struct sockaddr_in addr;
user userlist[MAX_USERS];
unsigned short usercount = 0;
unsigned short tcpconncount = 0;

jmp_buf jmp;

int main(int argc, char *argv[]) {
    loop = uv_default_loop();
    assert(loop != NULL);

    uv_tcp_t st;
    uv_signal_t sig;
    int listen;

    assert(init_tcp_s(loop, &st) == 0);
    listen = uv_listen((uv_stream_t*)&st, MAX_CONNECTIONS, conn_tcp);

    if (listen) {
        fprintf(stderr, "listen error: %s\n", uv_strerror(listen));
        return EXIT_FAILURE;
    }

    uv_timer_init(loop, &timer);
    uv_signal_init(loop, &sig);
    uv_signal_start(&sig, signal_handler, SIGINT);

    listen = setjmp(jmp);
    if (!listen) {
        uv_run(loop, UV_RUN_DEFAULT);
    }

    fprintf(stdout, "Closing uvs...\n");
    uv_loop_close(loop);
    freeall();
    exit(EXIT_SUCCESS);
}

int init_tcp_s(uv_loop_t *loop, uv_tcp_t *s) {
    return uv_tcp_init(loop, s) | uv_ip4_addr("0.0.0.0", LISTEN_PORT, &addr) | uv_tcp_bind(s, (const struct sockaddr*)&addr, 0);
}

void conn_tcp(uv_stream_t* s, int status) {
    fprintf(stdout, "new tcp connection incoming...\n");
    if (status < 0) {
        fprintf(stderr, "error with setting up new connections %s\n", uv_strerror(status));
        return;
    }
    tcpconn[tcpconncount] = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    if (tcpconn[tcpconncount] == NULL) {
        fprintf(stderr, "error with malloc for uv_tcp_t *tcpconn\n");
        return;
    }
    if (uv_tcp_init(loop, tcpconn[tcpconncount])) {
        fprintf(stderr ,"error with uv_tcp_init, within cb_conn_tcp\n");
        return;
    }
    if (uv_accept(s, (uv_stream_t*)tcpconn[tcpconncount]) == 0) {
        uv_read_start((uv_stream_t*)tcpconn[tcpconncount], set_buffer, read_msg);
    }
    tcpconncount++;
}

void read_msg(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    /*
     * example messages
     * n: Neo                   // registers user as Neo
     * a: hello                 // sends message "hello" to everyone
     * _t30: coffee?            // sends message "coffee?" to everyone in 30 seconds, whereas t20 would be 20 seconds
     * Trinity blue or red      // sends message "blue or red" to user with nick Trinity
     */
    if (nread > 0) {
        int msgop = -1;
        unsigned int delay = 0;

        wrt = (write_req_t*)malloc(sizeof(write_req_t));
        if (wrt == NULL) {
            fprintf(stderr ,"error with malloc for write_req_t *wrt\n");
            return;
        }

        // +2 for new line characters '\r\n'
        wrt->buf = uv_buf_init(buf->base, buf->len);
        wrt->buf.base = (char *)malloc(buf->len + 2);
        if (wrt->buf.base == NULL) {
            fprintf(stderr ,"error with malloc for wrt->buf.base\n");
            free(buf->base);
            return;
        }
        memcpy(wrt->buf.base, buf->base, buf->len);

        char *msg = wrt->buf.base;

        // latest libuv has thread-safe uv__strtok
        if (!strncmp(msg, "n:", 2)) {
            msg = strtok(msg, " ");
            msgop = NICKREG;

        } else if (!strncmp(msg, "a:", 2)) {
            msg = strstr(msg, ": ") + 2;
            msgop = ALL;

        } else if (!strncmp(msg, "_t", 2)) {
            delay = atoi(msg + 2);
            msg = strstr(msg, ": ") + 2;
            msgop = ALL_DELAY;

        } else {
            msgop = NICK;
        }

        if (msg == NULL) {
            msgop = -1;
        }

        // check if user is setting nickname for chatroom
        switch (msgop) {
            case -1:
                break;
            case NICKREG:
                // move by 3 chars: 'n: '
                msg += 3;
                if (usercount < MAX_USERS) {
                    // add nick to userlist[] if it doesn't already exist
                    for (int i = 0; i < usercount; i++) {
                        // do not allow double nick usage
                        if (client == userlist[i].stream) {
                            fprintf(stdout, "user %s has already a nick\n", userlist[i].nick);
                            uv_buf_t response = uv_buf_init("    you already have a nick!\n", 28);
                            prepare_message(client, &response);
                            send_message();
                            return;
                        }

                        if (!strncmp(userlist[i].nick, msg, NICK_LENGTH)) {
                            fprintf(stdout, "%s - nick exists already, impostor?\n", msg);
                            uv_buf_t response = uv_buf_init("    nick exists already, try something else\n", 44);
                            prepare_message(client, &response);
                            send_message();
                            msg = NULL;
                        }
                    }
                    // register new nick
                    if (msg) {
                        memcpy(userlist[usercount].nick, msg, NICK_LENGTH);
                        strncat(userlist[usercount].nick, "\r", 2);
                        userlist[usercount].stream = client;
                        fprintf(stdout, "new nick registered: %s", userlist[usercount].nick);
                        uv_buf_t response = uv_buf_init("    nick registered\n", 20);
                        prepare_message(client, &response);
                        send_message();
                        usercount++;
                    }

                } else {
                    fprintf(stdout, "user limit reached\n");
                    uv_buf_t response = uv_buf_init("    user limit reached, come back later\n", 40);
                    prepare_message(client, &response);
                    send_message();
                }
                break;

            case ALL:
            case ALL_DELAY:
                // send message to everyone
                size_t msglen = strlen(msg);
                for(int i = 0; i < usercount; i++) {
                    if (userlist[i].stream != NULL) {
                        userlist[i].buf = uv_buf_init(msg, msglen);
                        // +2 for new line characters '\r\n'
                        userlist[i].buf.base = (char *)malloc(msglen + 2);
                        if (userlist[i].buf.base == NULL) {
                            fprintf(stderr ,"error with malloc for userlist[i].buf.base\n");
                            continue;
                        }
                        memcpy(userlist[i].buf.base, msg, msglen);
                        strcat(userlist[i].buf.base, "\n");
                    }
                }

                if (msgop == ALL) {
                    fprintf(stdout, "sending following message to everyone:\n%s", msg);
                    message_all(&timer);
                } else if (msgop == ALL_DELAY) {
                    fprintf(stdout, "sending following timed message to everyone:\n%s", msg);
                    uv_timer_start(&timer, message_all, delay * 1000, 0);
                }

                break;

            case NICK:
                char *destnick = strtok(msg, " ");
                int destnicklen = strlen(destnick);
                int i = 0;

                for (i = 0; i < usercount; i++) {
                    if (!strncmp(destnick, userlist[i].nick, destnicklen)) {
                        prepare_message(userlist[i].stream, &wrt->buf);
                        send_message();
                        break;
                    }
                }
                if (i >= usercount) {
                    fprintf(stdout, "%s - nick does not exist\n", destnick);
                    uv_buf_t response = uv_buf_init("    nick does not exist\n", 24);
                    prepare_message(client, &response);
                    send_message();
                }
                break;

            default:
                break;
        }

    } else if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t*) client, on_close);
    }

    free(buf->base);
}

void message_all(uv_timer_t *handle) {
    for (int i = 0; i < usercount; i++) {
        if (userlist[i].stream != NULL) {
            write_req_t *wrt_l = (write_req_t*)malloc(sizeof(write_req_t));
            if (wrt_l == NULL) {
                fprintf(stderr, "malloc failure for write_req_t *wrt_l\n");
                continue;
            }
            wrt_l->buf = uv_buf_init(userlist[i].buf.base, userlist[i].buf.len);
            send_message_no_prep(wrt_l, userlist[i].stream, &userlist[i].buf);
        }
    }

    uv_timer_stop(handle);
}

void prepare_message(uv_stream_t *s, uv_buf_t *msg) {
    uvstrm = s;
    bufmsg = msg;
}

void send_message() {
    uv_write(&wrt->req, uvstrm, bufmsg, 1, msg_write);
}

void send_message_no_prep(write_req_t *wrt_l, uv_stream_t *s, uv_buf_t *msg) {
    uv_write((uv_write_t*)wrt_l, s, msg, 1, msg_write);
}

// stuff from libuv/docs/code/tcp-echo-server/main.c (some slightly modified):
void set_buffer(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    buf->base = (char*)malloc(size * sizeof(char*));
    buf->len = size;
}

void msg_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }
    free_write_req(req);
}

void signal_handler(uv_signal_t *handle, int signum) {
    fprintf(stdout, "Signal received: %d\n", signum);
    uv_signal_stop(handle);
    longjmp(jmp, 1);
}

void on_close(uv_handle_t* handle) {
    free(handle);
}

void free_write_req(uv_write_t *req) {
    write_req_t *wr = (write_req_t*)req;
    free(wr->buf.base);
    free(wr);
}

void freeall() {
    free(wrt);
    free(uvstrm);
    for (int i = 0; i < tcpconncount; i++) {
        free(tcpconn[i]);
    }
}
