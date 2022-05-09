#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <common/base64.h>
#include <postgres.h>
#include <postmaster/bgworker.h>
#include <utils/guc.h>

#define EXT_NAME "pg_websocket"

PG_MODULE_MAGIC;
void _PG_init(void);
void _PG_fini(void);

typedef enum {
    WS_OP_NONE = 0x00,
    WS_OP_DATA_BINARY = 0x02,
    WS_OP_CLOSE = 0x08,
    WS_OP_PING = 0x09,
    WS_OP_PONG = 0x0A,
} ws_opcode;

typedef enum {
    WS_FRONTEND_HANDSHAKE,
    WS_FRONTEND_CONNECTED,
    WS_BACKEND_STARTUP,
    WS_BACKEND_CONNECTED,
    WS_CLOSING,
} ws_state;

struct ws_buf {
    uint8_t buffer[8192];
    uint16_t len;
};
struct ws_conn {
    ws_state state;
    int fd;
    struct ws_buf write_buf;
    struct ws_buf read_buf;
    struct ws_conn* target;
    char auth[255];
};

// set from postgresql.conf:
static char* config_listen_port = NULL;
static char* config_backend_port = NULL;
static char* config_backend_host = NULL;
static char* config_auth_header_name = NULL;
static char* config_auth = NULL;

static bool run = true;

static bool ws_flush(struct ws_conn* ws) {
    for (uint16_t len = ws->write_buf.len; len > 0;) {
        ssize_t sent = write(ws->fd, ws->write_buf.buffer, len);
        if (sent < 0) {
            const int err = errno;
            if (err == EWOULDBLOCK) {
                break;
            }
            ereport(WARNING, errmsg(EXT_NAME " write: %s", strerror(err)));
            return false;
        }
        if (sent < (ssize_t) len) {
            memmove(ws->write_buf.buffer,
                    ws->write_buf.buffer + sent,
                    len - sent);
        }
        len = ws->write_buf.len = len - sent;
    }
    return true;
}

static bool ws_send(struct ws_conn* ws,
                    const uint8_t* data,
                    const uint16_t data_len) {
    if (ws->write_buf.len + data_len > sizeof(ws->write_buf)) {
        return false;
    }
    memcpy(ws->write_buf.buffer + ws->write_buf.len, data, data_len);
    ws->write_buf.len += data_len;
    return ws_flush(ws);
}

static bool ws_recv(struct ws_conn* ws, uint16_t* len_out) {
    ssize_t len = read(ws->fd,
                       ws->read_buf.buffer + ws->read_buf.len,
                       sizeof(ws->read_buf.buffer) - ws->read_buf.len - 1);
    if (len < 0) {
        const int err = errno;
        if (err == EWOULDBLOCK) {
            return true;
        }
        ereport(WARNING, errmsg(EXT_NAME " recv: %s", strerror(err)));
        return false;
    }
    ws->read_buf.len += len;
    ws->read_buf.buffer[ws->read_buf.len] = 0;
    *len_out = len;
    return true;
}

static bool ws_handshake_get_header(const char* request,
                                    const char* header_name,
                                    char* value_out,
                                    size_t value_out_len) {
    char header[255] = {0};
    sprintf(header, "%.252s: ", header_name);
    const char* crlf = "\r\n";
    for (char* start = strstr(request, crlf); start;
         start = strstr(start, crlf)) {
        start += strlen(crlf);
        if (strstr(start, header) == start) {
            const char* end = strstr(start, crlf);
            if (!end || end - start >= (ssize_t) value_out_len - 1) {
                break;
            }
            const size_t len = strlen(header);
            strncat(value_out, start + len, end - start - len);
            return true;
        }
    }
    return false;
}

static bool ws_handshake_hash_key(const char* key,
                                  char* hash_out,
                                  size_t hash_out_len) {
    const char* rfc_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t hash[20] = {0};
    SHA_CTX ctx = {0};
    return SHA1_Init(&ctx)                                    //
           && SHA1_Update(&ctx, key, strlen(key))             //
           && SHA1_Update(&ctx, rfc_magic, strlen(rfc_magic)) //
           && SHA1_Final(hash, &ctx)                          //
           && pg_b64_encode((char*) hash, sizeof(hash), hash_out, hash_out_len)
                  > 0;
}

static bool ws_handshake(struct ws_conn* ws) {
    if (!strstr((char*) ws->read_buf.buffer, "\r\n\r\n")) {
        return false;
    }
    char protocol[255] = {0};
    char key[255] = {0};
    char hash[255] = {0};
    if (!ws_handshake_get_header((char*) ws->read_buf.buffer,
                                 "Sec-WebSocket-Protocol",
                                 protocol,
                                 sizeof(protocol))
        || strcmp("binary", protocol)
        || !ws_handshake_get_header((char*) ws->read_buf.buffer,
                                    "Sec-WebSocket-Key",
                                    key,
                                    sizeof(key))
        || !ws_handshake_hash_key(key, //
                                  hash,
                                  sizeof(hash))) {
        const char* http_error = "HTTP/1.1 400 Bad Request\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n";
        ws_send(ws, (uint8_t*) http_error, strlen(http_error));
        ws->state = WS_CLOSING;
        return false;
    }

    char auth[255] = {0};
    if (strlen(config_auth_header_name)
        && ws_handshake_get_header((char*) ws->read_buf.buffer,
                                   config_auth_header_name,
                                   auth,
                                   sizeof(auth))) {
        strncat(ws->auth, auth, sizeof(ws->auth) - 1);
    }

    char http_response[1024] = {0};
    sprintf(http_response,
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Connection: Upgrade\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Protocol: binary\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n",
            hash);
    return ws_send(ws, (uint8_t*) http_response, strlen(http_response));
}

static bool ws_frame_decode(uint8_t* encoded,
                            const size_t len,
                            uint8_t* opcode_out,
                            uint8_t** decoded_out,
                            uint16_t* decoded_len,
                            uint16_t* header_len) {
    *decoded_len = *header_len = 0;
    if (len < 2) {
        return true;
    }
    uint8_t fin = encoded[0] & 0x80;
    uint8_t opcode = encoded[0] & 0x0f;
    uint8_t masked = encoded[1] & 0x80;
    uint16_t data_len = encoded[1] & 0x7F;
    if (!masked || data_len > 126) {
        ereport(WARNING,
                errmsg(EXT_NAME
                       " invalid websocket frame: (f=%u,o=%u,m=%u,l=%u)",
                       fin,
                       opcode,
                       masked,
                       data_len));
        return false;
    }
    uint8_t offset = 6;
    if (data_len == 126) {
        if (len < 4) {
            return true;
        }
        data_len = (encoded[2] << 8) | encoded[3];
        offset += 2;
    }
    if (offset + data_len > len) {
        return true;
    }
    for (uint16_t i = 0; i < data_len; i++) {
        encoded[offset + i] ^= (encoded + (offset - 4))[i % 4];
    }
    *opcode_out = opcode;
    *decoded_out = encoded + offset;
    *decoded_len = data_len;
    *header_len = offset;
    return true;
}

static void ws_frame_encode_header(const uint16_t len,
                                   const ws_opcode opcode,
                                   uint8_t* header,
                                   uint8_t* header_len) {
    header[0] = 0x80 | opcode;
    uint8_t offset = 2;
    if (len < 126) {
        header[1] = len;
    } else {
        header[1] = 126;
        header[offset++] = len >> 8;
        header[offset++] = len & 0xff;
    }
    *header_len = offset;
}

static bool ws_backend_connect(const struct ws_conn* ws,
                               const int epfd,
                               int* sockfd_out) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    struct addrinfo* addr = NULL;
    int err = getaddrinfo(config_backend_host, //
                          config_backend_port,
                          &hints,
                          &addr);
    if (err) {
        ereport(WARNING,
                errmsg(EXT_NAME " backend host '%s' not found: %s",
                       config_backend_host,
                       gai_strerror(err)));
        return false;
    }

    int sockfd = socket(addr->ai_family,
                        SOCK_STREAM | SOCK_NONBLOCK,
                        addr->ai_protocol);
    if (sockfd < 0 || connect(sockfd, addr->ai_addr, addr->ai_addrlen)) {
        err = errno;
        if (!(sockfd > 0 && err == EINPROGRESS)) {
            ereport(WARNING,
                    errmsg(EXT_NAME " backend connect: %s", strerror(err)));
            freeaddrinfo(addr);
            if (sockfd > 0) {
                close(sockfd);
            }
            return false;
        }
    }
    freeaddrinfo(addr);
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  sockfd,
                  &(struct epoll_event){
                      .events = EPOLLIN | EPOLLOUT | EPOLLET //
                                | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = (void*) ws,
                  })) {
        err = errno;
        ereport(WARNING, errmsg(EXT_NAME " backend epoll: %s", strerror(err)));
        close(sockfd);
        return false;
    }
    *sockfd_out = sockfd;
    return true;
}

static bool ws_handshake_complete(struct ws_conn* ws, const int epfd) {
    ws->state = WS_FRONTEND_CONNECTED;
    ws->read_buf.len = 0;
    struct ws_conn* backend = calloc(1, sizeof(struct ws_conn));
    if (!ws_backend_connect(backend, epfd, &backend->fd)) {
        free(backend);
        return false;
    }
    backend->state = WS_BACKEND_STARTUP;
    backend->read_buf.len = 0;
    backend->write_buf.len = 0;
    backend->target = ws;
    ws->target = backend;
    return true;
}

static bool ws_send_ping_response(struct ws_conn* ws,
                                  const uint8_t* data,
                                  const uint16_t data_len) {
    uint8_t header[4];
    uint8_t header_len = 0;
    ws_frame_encode_header(ws->read_buf.len, WS_OP_PONG, header, &header_len);
    return ws_send(ws, header, header_len) && ws_send(ws, data, data_len);
}

static bool ws_add_auth_to_startup_packet(uint8_t* decoded,
                                          uint16_t decoded_len,
                                          uint16_t buf_len,
                                          uint16_t* len_out,
                                          char* auth) {
    if (!strlen(auth)) {
        *len_out = decoded_len;
        return true;
    }

    uint32_t msg_len = ntohl(*(uint32_t*) decoded);
    char options[1024];
    uint32_t options_len = 0;
    const char prefix[] = "options\0-c websocket.authentication=";
    memcpy(options, prefix, sizeof(prefix) - 1);
    options_len = sizeof(prefix) - 1;
    memcpy(options + options_len, auth, strlen(auth));
    options_len += strlen(auth);
    options[options_len++] = 0;
    options[options_len++] = 0;

    uint32_t startup_len = msg_len + options_len - 1;
    if (startup_len > buf_len) {
        return false;
    }
    memcpy(decoded + msg_len - 1, options, options_len);
    uint32_t be = htonl(startup_len);
    memcpy(decoded, &be, 4);

    *len_out = msg_len + options_len - 1;
    return true;
}

static bool ws_handle_frontend_read(struct ws_conn* ws) {
    uint8_t opcode = 0;
    uint8_t* decoded = NULL;
    uint16_t decoded_len = 0;
    uint16_t header_len = 0;
    while (ws->read_buf.len > 0) {
        if (!ws_frame_decode(ws->read_buf.buffer,
                             ws->read_buf.len,
                             &opcode,
                             &decoded,
                             &decoded_len,
                             &header_len)) {
            return false;
        }
        if (header_len == 0) {
            return true;
        }
        if (opcode == WS_OP_CLOSE) {
            return false;
        }
        if (opcode == WS_OP_DATA_BINARY || opcode == WS_OP_NONE) {
            if (ws->target->state == WS_BACKEND_STARTUP) {
                uint16_t startup_len = 0;
                if (!ws_add_auth_to_startup_packet(decoded,
                                                   decoded_len,
                                                   sizeof(ws->read_buf)
                                                       - ws->read_buf.len,
                                                   &startup_len,
                                                   ws->auth)
                    || !ws_send(ws->target, decoded, startup_len)) {
                    return false;
                }
                ws->target->state = WS_BACKEND_CONNECTED;
            } else if (!ws_send(ws->target, decoded, decoded_len)) {
                return false;
            }
        } else if (opcode == WS_OP_PING) {
            if (!ws_send_ping_response(ws, decoded, decoded_len)) {
                return false;
            }
        }
        uint16_t remaining = ws->read_buf.len - header_len - decoded_len;
        if (remaining > 0) {
            memmove(ws->read_buf.buffer,
                    ws->read_buf.buffer + header_len + decoded_len,
                    remaining);
        }
        ws->read_buf.len = remaining;
    }
    return true;
}

static bool ws_send_to_frontend(struct ws_conn* ws) {
    struct ws_conn* frontend = ws->target;
    uint8_t header[4];
    uint8_t header_len = 0;
    ws_frame_encode_header(ws->read_buf.len,
                           WS_OP_DATA_BINARY,
                           header,
                           &header_len);
    if (!ws_send(frontend, header, header_len)
        || !ws_send(frontend, ws->read_buf.buffer, ws->read_buf.len)) {
        return false;
    }
    ws->read_buf.len = 0;
    return true;
}

static bool ws_handle_read_event(struct ws_conn* ws, const int epfd) {
    while (ws->state != WS_CLOSING) {
        uint16_t len = 0;
        if (!ws_recv(ws, &len)) {
            return false;
        }
        if (len == 0) {
            return true;
        }
        if (ws->state == WS_FRONTEND_HANDSHAKE) {
            if (ws_handshake(ws) && !ws_handshake_complete(ws, epfd)) {
                return false;
            }
        } else if (ws->state == WS_FRONTEND_CONNECTED) {
            if (!ws_handle_frontend_read(ws)) {
                return false;
            }
        } else if (ws->state == WS_BACKEND_CONNECTED) {
            if (!ws_send_to_frontend(ws)) {
                return false;
            }
        }
    }
    return true;
}

static void ws_close(struct ws_conn* ws, const int epfd) {
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, ws->fd, NULL) || close(ws->fd)) {
        const int err = errno;
        ereport(WARNING, errmsg(EXT_NAME " close: %s", strerror(err)));
    }
    if (ws->target) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, ws->target->fd, NULL)
            || close(ws->target->fd)) {
            const int err = errno;
            ereport(WARNING,
                    errmsg(EXT_NAME " close target: %s", strerror(err)));
        }
        free(ws->target);
    }
    free(ws);
}

static bool ws_handle_client_event(struct ws_conn* ws,
                                   const uint32_t events,
                                   const int epfd) {
    if (events & EPOLLIN) {
        if (!ws_handle_read_event(ws, epfd)) {
            ws->state = WS_CLOSING;
            return false;
        }
    }
    if (events & EPOLLOUT && ws->state != WS_CLOSING) {
        if (!ws_flush(ws)) {
            ws->state = WS_CLOSING;
            return false;
        }
    }
    if (events & (EPOLLRDHUP | EPOLLHUP) || ws->state == WS_CLOSING) {
        ws->state = WS_CLOSING;
        return false;
    }
    return true;
}

static void ws_handle_server_event(const int sockfd, const int epfd) {
    struct sockaddr_in addr = {0};
    int clientfd = accept4(sockfd,
                           (struct sockaddr*) &addr,
                           &(socklen_t){sizeof(addr)},
                           SOCK_NONBLOCK);
    if (clientfd < 0) {
        const int err = errno;
        ereport(WARNING, errmsg(EXT_NAME " accept: %s", strerror(err)));
        return;
    }
    struct ws_conn* ws = calloc(1, sizeof(struct ws_conn));
    ws->fd = clientfd;
    ws->state = WS_FRONTEND_HANDSHAKE;
    ws->read_buf.len = 0;
    ws->write_buf.len = 0;
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  clientfd,
                  &(struct epoll_event){
                      .events = EPOLLIN | EPOLLOUT | EPOLLET //
                                | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = ws,
                  })) {
        const int err = errno;
        ereport(WARNING, errmsg(EXT_NAME " accept epoll: %s", strerror(err)));
        free(ws);
    }
}

static void ws_main_loop(const int sockfd, const int epfd) {
    struct epoll_event events[64];
    uint64_t closed_conns[64 * 2];
    while (run) {
        int32_t n = epoll_wait(epfd, events, 64, -1);
        if (n < 0) {
            const int err = errno;
            if (err == EAGAIN) {
                continue;
            }
            ereport(WARNING, errmsg(EXT_NAME " epoll: %s", strerror(err)));
            break;
        }
        uint16_t closed_len = 0;
        for (int32_t i = 0; i < n; i++) {
            struct ws_conn* ws = events[i].data.ptr;
            if (!ws) {
                ws_handle_server_event(sockfd, epfd);
                continue;
            }
            uint64_t conn_id = events[i].data.u64;
            for (uint16_t j = 0; j < closed_len; j++) {
                if (closed_conns[j] == conn_id) {
                    conn_id = 0;
                    break;
                }
            }
            if (conn_id
                && !ws_handle_client_event(ws, events[i].events, epfd)) {
                closed_conns[closed_len++] = conn_id;
                if (ws->target) {
                    closed_conns[closed_len++] = (uint64_t) ws->target;
                }
                ws_close(ws, epfd);
            }
        }
    }
}

static bool ws_create_epoll(const int sockfd, int* epfd_out) {
    int epfd = epoll_create1(0);
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  sockfd,
                  &(struct epoll_event){
                      .events = EPOLLIN | EPOLLOUT | EPOLLET,
                      .data.ptr = NULL,
                  })) {
        const int err = errno;
        ereport(WARNING, errmsg(EXT_NAME " create epoll: %s", strerror(err)));
        close(epfd);
        return false;
    }
    *epfd_out = epfd;
    return true;
}

static bool ws_listen(const uint16_t port, int* fd_out) {
    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        return false;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int32_t){1}, 4)
        || setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int32_t){1}, 4)
        || bind(sockfd, (struct sockaddr*) &addr, sizeof(addr))
        || listen(sockfd, 64)) {
        const int err = errno;
        if (err != EINPROGRESS) {
            ereport(WARNING,
                    errmsg(EXT_NAME " listen failed: %s", strerror(err)));
            close(sockfd);
            return false;
        }
    }
    *fd_out = sockfd;
    return true;
}

static void ws_sighandler(SIGNAL_ARGS) {
    ereport(DEBUG1, errmsg(EXT_NAME " stopping"));
    run = false;
}

void ws_main(Datum);
void ws_main(Datum arg) {
    pqsignal(SIGTERM, ws_sighandler);
    pqsignal(SIGINT, SIG_IGN);
    BackgroundWorkerUnblockSignals();

    const int port = atoi(config_listen_port);
    if (port < 1) {
        ereport(WARNING,
                errmsg(EXT_NAME " invalid port: %s", config_listen_port));
        return;
    }
    int sockfd = 0;
    int epfd = 0;
    if (ws_listen(port, &sockfd) && ws_create_epoll(sockfd, &epfd)) {
        ereport(LOG, errmsg(EXT_NAME " listening on port %u", port));
        ws_main_loop(sockfd, epfd);
    }
    ereport(LOG, errmsg(EXT_NAME " stopped"));
    if (sockfd) {
        close(sockfd);
    }
    if (epfd) {
        close(epfd);
    }
}

void _PG_init(void) {
    DefineCustomStringVariable("websocket.port",
                               gettext_noop("pg_websocket listen port."),
                               NULL,
                               &config_listen_port,
                               "15432",
                               PGC_POSTMASTER,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);
    DefineCustomStringVariable("websocket.pg_host",
                               gettext_noop("pg_websocket target host."),
                               NULL,
                               &config_backend_host,
                               "localhost",
                               PGC_POSTMASTER,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);
    DefineCustomStringVariable("websocket.pg_port",
                               gettext_noop("pg_websocket target port."),
                               NULL,
                               &config_backend_port,
                               "5432",
                               PGC_POSTMASTER,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);
    DefineCustomStringVariable("websocket.authentication_header_name",
                               gettext_noop(
                                   "pg_websocket name of authentication "
                                   "header to pass to backend."),
                               NULL,
                               &config_auth_header_name,
                               "",
                               PGC_POSTMASTER,
                               GUC_SUPERUSER_ONLY,
                               NULL,
                               NULL,
                               NULL);
    DefineCustomStringVariable("websocket.authentication",
                               gettext_noop(
                                   "pg_websocket authentication variable."),
                               NULL,
                               &config_auth,
                               "",
                               PGC_BACKEND,
                               GUC_DISALLOW_IN_FILE,
                               NULL,
                               NULL,
                               NULL);

    BackgroundWorker worker = {0};
    worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
    worker.bgw_restart_time = 60;
    worker.bgw_notify_pid = 0;
    snprintf(worker.bgw_name, BGW_MAXLEN, EXT_NAME);
    snprintf(worker.bgw_library_name, BGW_MAXLEN, EXT_NAME);
    snprintf(worker.bgw_function_name, BGW_MAXLEN, "ws_main");
    RegisterBackgroundWorker(&worker);
}

void _PG_fini(void) {
}
