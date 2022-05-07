#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/base64.h>
#include <openssl/sha.h>

#define BACKEND_PORT 5432
#define BACKEND_IP "127.0.0.1"
#define MAX_EVENTS 128

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
};

const char* crlf = "\r\n";
const char* rfc_magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static bool ws_flush(struct ws_conn* ws) {

    for (uint16_t len = ws->write_buf.len; len > 0;) {
        ssize_t sent = write(ws->fd, ws->write_buf.buffer, len);
        if (sent < 0) {
            const int err = errno;
            if (err == EWOULDBLOCK) {
                break;
            }
            printf("write: %s\n", strerror(err));
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

static bool ws_send(struct ws_conn* ws, uint8_t* data, uint16_t data_len) {

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
        printf("read: %s\n", strerror(err));
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
        printf("invalid websocket frame: (f=%u,o=%u,m=%u,l=%u)\n",
               fin,
               opcode,
               masked,
               data_len);
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
                                   ws_opcode opcode,
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

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &addr.sin_addr);
    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        return false;
    }
    if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr))) {
        const int err = errno;
        if (err != EINPROGRESS) {
            printf("ws_backend_connect: %s\n", strerror(err));
            close(sockfd);
            return false;
        }
    }
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  sockfd,
                  &(struct epoll_event){
                      .events
                      = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = (void*) ws,
                  })) {
        perror("epoll_ctl");
        close(sockfd);
        return false;
    }
    printf("connected to backend\n");
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
    backend->state = WS_BACKEND_CONNECTED;
    backend->read_buf.len = 0;
    backend->write_buf.len = 0;
    backend->target = ws;
    ws->target = backend;
    return true;
}

static bool ws_send_ping_response(struct ws_conn* ws,
                                  uint8_t* data,
                                  uint16_t data_len) {
    uint8_t header[4];
    uint8_t header_len = 0;
    ws_frame_encode_header(ws->read_buf.len, WS_OP_PONG, header, &header_len);
    return ws_send(ws, header, header_len) && ws_send(ws, data, data_len);
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
            if (!ws_send(ws->target, decoded, decoded_len)) {
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

    while (true) {
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

static void ws_close(struct ws_conn* ws, int epfd) {
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, ws->fd, NULL)) {
        perror("epoll_ctl");
    }
    close(ws->fd);
    if (ws->target) {
        if (epoll_ctl(epfd, EPOLL_CTL_DEL, ws->target->fd, NULL)) {
            perror("epoll_ctl");
        }
        close(ws->target->fd);
        free(ws->target);
    }
    free(ws);
}

static void ws_handle_client_event(const struct epoll_event* event,
                                   const int epfd) {

    struct ws_conn* ws = event->data.ptr;
    if (event->events & EPOLLIN) {
        printf("  EPOLLIN\n");
        if (!ws_handle_read_event(ws, epfd)) {
            printf("client read failed\n");
            ws->state = WS_CLOSING;
        }
    }
    if (event->events & EPOLLOUT && ws->state != WS_CLOSING) {
        printf("  EPOLLOUT\n");
        if (!ws_flush(ws)) {
            printf("client write failed\n");
            ws->state = WS_CLOSING;
        }
    }
    if (event->events & (EPOLLRDHUP | EPOLLHUP) || ws->state == WS_CLOSING) {
        printf("  CLOSE\n");
        printf("close event\n");
        ws_close(ws, epfd);
    }
}

static bool ws_handle_server_event(const int sockfd, const int epfd) {

    struct sockaddr_in addr = {0};
    int clientfd = accept4(sockfd,
                           (struct sockaddr*) &addr,
                           &(socklen_t){sizeof(addr)},
                           SOCK_NONBLOCK);
    if (clientfd < 0) {
        perror("accept4");
        return false;
    }
    printf("client connected\n");
    struct ws_conn* ws = calloc(1, sizeof(struct ws_conn));
    ws->fd = clientfd;
    ws->state = WS_FRONTEND_HANDSHAKE;
    ws->read_buf.len = 0;
    ws->write_buf.len = 0;
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  clientfd,
                  &(struct epoll_event){
                      .events
                      = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = ws,
                  })) {
        perror("epoll_ctl");
        free(ws);
        return false;
    }
    return true;
}

static void ws_main_loop(const int sockfd, const int epfd) {

    struct epoll_event events[MAX_EVENTS];
    while (true) {
        int32_t n = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (n < 0) {
            perror("epoll_wait");
            break;
        }
        printf("got %d events\n", n);
        for (int32_t i = 0; i < n; i++) {
            if (events[i].data.ptr != NULL) {
                ws_handle_client_event(&events[i], epfd);
            } else if (!ws_handle_server_event(sockfd, epfd)) {
                printf("client accept failed");
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
        perror("epoll_ctl");
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
            printf("ws_listen: %s\n", strerror(err));
            close(sockfd);
            return false;
        }
    }
    *fd_out = sockfd;
    return true;
}

int main(void) {

    int sockfd = 0;
    int epfd = 0;
    if (ws_listen(15432, &sockfd) && ws_create_epoll(sockfd, &epfd)) {
        ws_main_loop(sockfd, epfd);
    }
    if (sockfd) {
        close(sockfd);
    }
    if (epfd) {
        close(epfd);
    }
    return 0;
}
