/*
cc -I/usr/include/postgresql/13/server -o test src/test.c
-L/usr/lib/postgresql/13/lib -lpgcommon -lcrypto -lm
*/

#define _GNU_SOURCE

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

typedef enum {
    WS_FE_HANDSHAKE,
    WS_FE_CONNECTED,
    WS_BACKEND,
} ws_state;

struct ws_buf {
    ws_state state;
    int fd;
    size_t len;
    size_t pos;
    uint8_t buffer[8192];
    void* next;
};

static const char* crlf = "\r\n";

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
            if (!end || end - start >= (ssize_t)value_out_len - 1) {
                break;
            }
            const size_t len = strlen(header);
            strncat(value_out, start + len, end - start - len);
            return true;
        }
    }
    return false;
}

static bool
ws_handshake_hash_key(const char* key, char* hash_out, size_t hash_out_len) {

    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t hash[20] = {0};
    SHA_CTX ctx = {0};
    return SHA1_Init(&ctx) && SHA1_Update(&ctx, key, strlen(key))
           && SHA1_Update(&ctx, magic, strlen(magic)) && SHA1_Final(hash, &ctx)
           && pg_b64_encode((char*)hash, sizeof(hash), hash_out, hash_out_len)
                  > 0;
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
        || bind(sockfd, (struct sockaddr*)&addr, sizeof(addr))
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

static bool ws_frontend_accept(const int sockfd, const int epfd) {

    struct sockaddr_in addr = {0};
    int clientfd = accept4(sockfd,
                           (struct sockaddr*)&addr,
                           &(socklen_t){sizeof(addr)},
                           SOCK_NONBLOCK);
    if (clientfd < 0) {
        perror("accept4");
        return false;
    }
    printf("client connected\n");
    struct ws_buf* ws = calloc(1, sizeof(struct ws_buf));
    ws->fd = clientfd;
    ws->state = WS_FE_HANDSHAKE;
    ws->len = ws->pos = 0;
    if (epoll_ctl(epfd,
                  EPOLL_CTL_ADD,
                  clientfd,
                  &(struct epoll_event){
                      .events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = ws,
                  })) {
        perror("epoll_ctl");
        free(ws);
        return false;
    }
    return true;
}

static bool ws_frontend_handshake(const struct ws_buf* ws) {

    char protocol[255] = {0};
    char key[255] = {0};
    if (!strstr((char*)ws->buffer, "\r\n\r\n")
        || !ws_handshake_get_header((char*)ws->buffer,
                                    "Sec-WebSocket-Protocol",
                                    protocol,
                                    sizeof(protocol))
        || strcmp("binary", protocol)
        || !ws_handshake_get_header(
            (char*)ws->buffer, "Sec-WebSocket-Key", key, sizeof(key))) {
        return false;
    }
    char hash[255] = {0};
    if (!ws_handshake_hash_key(key, hash, sizeof(hash))) {
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
    ssize_t http_response_len = strlen(http_response);
    if (write(ws->fd, http_response, http_response_len) != http_response_len) {
        printf("incomplete write\n");
    }
    return true;
}

static bool
ws_backend_connect(const struct ws_buf* ws, const int epfd, int* sockfd_out) {

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BACKEND_PORT);
    inet_pton(AF_INET, BACKEND_IP, &addr.sin_addr);
    int sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sockfd < 0) {
        return false;
    }
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr))) {
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
                      .events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP,
                      .data.ptr = (void*)ws,
                  })) {
        perror("epoll_ctl");
        close(sockfd);
        return false;
    }
    printf("connected to backend\n");
    *sockfd_out = sockfd;
    return true;
}

static void
ws_encode_frame(const uint16_t len, uint8_t* header, uint8_t* header_len) {

    header[0] = 0x80 | 0x02;
    uint8_t offset = 2;
    if (len < 126) {
        header[1] = len;
    } else {
        header[1] = 126;
        header[2] = len >> 8;
        header[3] = len & 0xff;
        offset += 2;
    }
    *header_len = offset;
}

static bool ws_decode_frame(uint8_t* encoded,
                            const size_t len,
                            uint8_t** decoded_out,
                            uint16_t* decoded_len) {
    uint8_t fin = encoded[0] & 0x80;
    uint8_t opcode = encoded[0] & 0x0f;
    uint8_t mask = encoded[1] & 0x80;
    uint16_t data_len = (uint8_t)(encoded[1] & 0x7F);
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

static bool ws_frontend_read(struct ws_buf* ws, const int epfd) {
    while (true) {
        ssize_t len = read(
            ws->fd, ws->buffer + ws->len, sizeof(ws->buffer) - ws->len - 1);
        if (len <= 0) {
            break;
        }
        printf("client read %ld (from %ld)\n", len, ws->len);
        ws->len += len;
        ws->buffer[ws->len] = 0;

        if (ws->state == WS_FE_HANDSHAKE) {
            if (ws_frontend_handshake(ws)) {
                ws->state = WS_FE_CONNECTED;
                ws->len = ws->pos = 0;
                struct ws_buf* backend = calloc(1, sizeof(struct ws_buf));
                backend->len = backend->pos = 0;
                backend->state = WS_BACKEND;
                if (!ws_backend_connect(backend, epfd, &backend->fd)) {
                    free(backend);
                    return false;
                }
                ws->next = backend;
                backend->next = ws;
            }
        } else if (ws->state == WS_FE_CONNECTED) {
            struct ws_buf* backend = ws->next;
            uint8_t* decoded = NULL;
            uint16_t decoded_len = 0;
            if (ws_decode_frame(ws->buffer, ws->len, &decoded, &decoded_len)) {
                ssize_t w = write(backend->fd, decoded, decoded_len);
                printf("wrote to backend(%u): %ld/%u\n",
                       backend->state,
                       w,
                       decoded_len);
                ws->len = ws->pos = 0;
            }
        } else {
            struct ws_buf* frontend = ws->next;
            uint8_t header[4];
            uint8_t header_len = 0;
            ws_encode_frame(ws->len, header, &header_len);
            ssize_t w1 = write(frontend->fd, header, header_len);
            ssize_t w2 = write(frontend->fd, ws->buffer, ws->len);
            printf("wrote to frontend(%u): %ld+%ld/%lu\n",
                   frontend->state,
                   w1,
                   w2,
                   header_len + ws->len);
            ws->len = ws->pos = 0;
        }
    }
    return true;
}

static void ws_handle_event(const struct epoll_event* event, const int epfd) {
    if (event->events & EPOLLIN) {
        if (!ws_frontend_read(event->data.ptr, epfd)) {
            printf("client read failed");
        }
    }
    if (event->events & EPOLLOUT) {
        printf("out event\n");
    }
    if (event->events & (EPOLLRDHUP | EPOLLHUP)) {
        printf("closing\n");
        struct ws_buf* buf = event->data.ptr;
        if (buf) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, buf->fd, NULL);
            close(buf->fd);
            struct ws_buf* next = buf->next;
            if (next) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, next->fd, NULL);
                close(next->fd);
                free(next);
            }
            free(buf);
        }
    }
}

static void ws_main_loop(const int sockfd, const int epfd) {
    const int32_t max_events = 64;
    struct epoll_event events[max_events];
    while (true) {
        int32_t n = epoll_wait(epfd, events, max_events, -1);
        if (n < 0) {
            perror("epoll_wait");
            break;
        }
        printf("got %d events\n", n);
        for (int32_t i = 0; i < n; i++) {
            if (events[i].data.ptr != NULL) {
                ws_handle_event(&events[i], epfd);
            } else if (!ws_frontend_accept(sockfd, epfd)) {
                printf("client accept failed");
            }
        }
    }
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
