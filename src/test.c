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
    WS_FE_HANDSHAKE,
    WS_FE_CONNECTED,
    WS_BACKEND,
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

static bool ws_flush(struct ws_conn* ws) {
    for (uint16_t len = ws->write_buf.len; len > 0;) {
        ssize_t sent = write(ws->fd, ws->write_buf.buffer, len);
        if (sent < 1) {
            const int err = errno;
            if (err == EAGAIN) {
                break;
            }
            printf("write: %s\n", strerror(err));
            return false;
        }
        if (sent == (ssize_t) len) {
            ws->write_buf.len = 0;
            break;
        }
        memmove(ws->write_buf.buffer, ws->write_buf.buffer + sent, len - sent);
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

static bool ws_handshake(struct ws_conn* ws) {

    char protocol[255] = {0};
    char key[255] = {0};
    char hash[255] = {0};
    if (!strstr((char*) ws->read_buf.buffer, "\r\n\r\n")
        || !ws_handshake_get_header((char*) ws->read_buf.buffer,
                                    "Sec-WebSocket-Protocol",
                                    protocol,
                                    sizeof(protocol))
        || strcmp("binary", protocol)
        || !ws_handshake_get_header((char*) ws->read_buf.buffer, //
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
                            uint8_t** decoded_out,
                            uint16_t* decoded_len) {

    uint8_t fin = encoded[0] & 0x80;
    uint8_t opcode = encoded[0] & 0x0f;
    uint8_t mask = encoded[1] & 0x80;
    uint16_t data_len = encoded[1] & 0x7F;
    if (!fin || !mask || opcode != 0x02 || data_len > 126) {
        printf("invalid websocket frame: (f=%u,o=%u,m=%u,l=%u)\n",
               fin,
               opcode,
               mask,
               data_len);
        return false;
    }
    uint8_t offset = 6;
    if (data_len == 126) {
        data_len = (encoded[2] << 8) | encoded[3];
        offset += 2;
    }
    if (offset + data_len > len) {
        printf("len outside buffer (%u + %u / %lu)\n", offset, data_len, len);
        return false;
    }
    for (uint16_t i = 0; i < data_len; i++) {
        encoded[offset + i] ^= (encoded + (offset - 4))[i % 4];
    }
    *decoded_out = encoded + offset;
    *decoded_len = data_len;
    return true;

    /*
    printf("FIN: %u\n", fin != 0);
    printf("opcode binary: %u\n", opcode == 0x02);
    printf("mask: %u\n", mask != 0);
    printf("len1: %u\n", len1);

    printf("masking key: %02x%02x%02x%02x\n",
           frame[2],
           frame[3],
           frame[4],
           frame[5]);
    printf("application data:\n  ");
    for (int i = 0; i < len1; i++) {
        printf("%02x", frame[offset + i]);
        if ((i + 1) % 2 == 0) {
            printf((i + 1) % 16 == 0 ? "\n  " : " ");
        }
    }
    printf("\n");
        */
}

static void ws_frame_encode_header(const uint16_t len,
                                   uint8_t* header,
                                   uint8_t* header_len) {

    header[0] = 0x80 | 0x02;
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

static bool ws_handle_read_event(struct ws_conn* ws, const int epfd) {

    while (true) {
        ssize_t len = read(ws->fd,
                           ws->read_buf.buffer + ws->read_buf.len,
                           sizeof(ws->read_buf.buffer) - ws->read_buf.len - 1);
        if (len <= 0) {
            break;
        }
        printf("client read %ld (from %u)\n", len, ws->read_buf.len);
        ws->read_buf.len += len;
        ws->read_buf.buffer[ws->read_buf.len] = 0;

        if (ws->state == WS_FE_HANDSHAKE) {
            if (ws_handshake(ws)) {
                ws->state = WS_FE_CONNECTED;
                ws->read_buf.len = 0;
                struct ws_conn* backend = calloc(1, sizeof(struct ws_conn));
                backend->read_buf.len = 0;
                backend->write_buf.len = 0;
                backend->state = WS_BACKEND;
                if (!ws_backend_connect(backend, epfd, &backend->fd)) {
                    free(backend);
                    return false;
                }
                ws->target = backend;
                backend->target = ws;
            }
        } else if (ws->state == WS_FE_CONNECTED) {
            struct ws_conn* backend = ws->target;
            uint8_t* decoded = NULL;
            uint16_t decoded_len = 0;
            if (ws_frame_decode(ws->read_buf.buffer,
                                ws->read_buf.len,
                                &decoded,
                                &decoded_len)) {
                ws_send(backend, decoded, decoded_len);
                ws->read_buf.len = 0;
            }
        } else {
            struct ws_conn* frontend = ws->target;
            uint8_t header[4];
            uint8_t header_len = 0;
            ws_frame_encode_header(ws->read_buf.len, header, &header_len);
            ws_send(frontend, header, header_len);
            ws_send(frontend, ws->read_buf.buffer, ws->read_buf.len);
            ws->read_buf.len = 0;
        }
    }
    return true;
}

static void ws_handle_client_event(const struct epoll_event* event,
                                   const int epfd) {

    struct ws_conn* ws = event->data.ptr;
    if (event->events & EPOLLIN) {
        if (!ws_handle_read_event(ws, epfd)) {
            printf("client read failed\n");
        }
    }
    if (event->events & EPOLLOUT) {
        printf("out event\n");
        if (!ws_flush(ws)) {
            printf("client write failed\n");
        }
    }
    if (event->events & (EPOLLRDHUP | EPOLLHUP)) {
        printf("closing client\n");
        if (ws) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, ws->fd, NULL);
            close(ws->fd);
            if (ws->target) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, ws->target->fd, NULL);
                close(ws->target->fd);
                free(ws->target);
            }
            free(ws);
        }
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
    ws->state = WS_FE_HANDSHAKE;
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
