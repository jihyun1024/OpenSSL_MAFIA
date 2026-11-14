#define _POSIX_C_SOURCE 200809L
#include "client.h"
#include "game.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int fd;
    sec_channel channel;
    EVP_PKEY* self_key;
    EVP_PKEY* server_pub;
    unsigned char self_id[CLIENT_ID_BYTE];
    int channel_ready;

    pthread_mutex_t lock;
    int running;
    int completed;
    int my_slot;
    int my_turn;
    int vote_phase;
    int vote_pending;   // 투표를 보내고 서버 응답을 기다리는 중
    int commit_received;
    unsigned char commit[SHA256_BYTE];
} client_ctx;

static int send_pubkey(int fd, EVP_PKEY* key) {
    unsigned char* der = NULL;
    int der_len = i2d_PUBKEY(key, &der);
    if (der_len <= 0) return 0;
    int success = io_write_blob(fd, der, (size_t)der_len);
    OPENSSL_free(der);
    return success;
}

static EVP_PKEY* recv_pubkey(int fd) {
    unsigned char buffer[4096];
    size_t len = sizeof buffer;
    if (io_read_blob(fd, buffer, &len) != 1) return NULL;
    const unsigned char* cursor = buffer;
    EVP_PKEY* key = d2i_PUBKEY(NULL, &cursor, (long)len);
    if (key == NULL || cursor != buffer + len ||
        EVP_PKEY_get_base_id(key) != EVP_PKEY_RSA ||
        EVP_PKEY_get_bits(key) != RSA_KEY_BIT) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

// 최초 접속에서는 서버 공개키를 기록하고, 이후에는 같은 키만 허용한다(TOFU).
static int server_key_pin(const char* key_path, EVP_PKEY* server_key,
                          int create_if_missing) {
    int success = 0;
    int created = 0;
    int fd = -1;
    unsigned char* der = NULL;
    unsigned char* stored = NULL;
    struct stat st;

    int der_len = i2d_PUBKEY(server_key, &der);
    if (der_len <= 0) return 0;
    size_t pin_len = strlen(key_path) + sizeof ".server.pub";
    char* pin_path = malloc(pin_len);
    if (pin_path == NULL) goto done;
    snprintf(pin_path, pin_len, "%s.server.pub", key_path);

    fd = open(pin_path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT && create_if_missing) {
        fd = open(pin_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  S_IRUSR | S_IWUSR);
        if (fd < 0 && errno == EEXIST) {
            free(pin_path);
            OPENSSL_free(der);
            return server_key_pin(key_path, server_key, 0);
        }
        if (fd < 0) goto pin_done;
        created = 1;

        size_t offset = 0;
        while (offset < (size_t)der_len) {
            ssize_t written = write(fd, der + offset, (size_t)der_len - offset);
            if (written < 0) {
                if (errno == EINTR) continue;
                goto pin_done;
            }
            if (written == 0) goto pin_done;
            offset += (size_t)written;
        }
        success = fsync(fd) == 0;
        goto pin_done;
    }
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size != der_len)
        goto pin_done;

    stored = malloc((size_t)der_len);
    if (stored == NULL) goto pin_done;
    size_t offset = 0;
    while (offset < (size_t)der_len) {
        ssize_t count = read(fd, stored + offset, (size_t)der_len - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            goto pin_done;
        }
        if (count == 0) goto pin_done;
        offset += (size_t)count;
    }
    success = CRYPTO_memcmp(stored, der, (size_t)der_len) == 0;

pin_done:
    if (fd >= 0) close(fd);
    if (created && !success) unlink(pin_path);
    free(pin_path);
done:
    free(stored);
    OPENSSL_free(der);
    return success;
}

static int server_pin_exists(const char* key_path) {
    size_t pin_len = strlen(key_path) + sizeof ".server.pub";
    char* pin_path = malloc(pin_len);
    if (pin_path == NULL) return 0;
    snprintf(pin_path, pin_len, "%s.server.pub", key_path);
    int exists = access(pin_path, F_OK) == 0;
    free(pin_path);
    return exists;
}

static int do_client_handshake(client_ctx* client) {
    handshake_ctx handshake;
    if (hs_ctx_init(&handshake, client->self_key, client->server_pub) != 1) return 0;

    unsigned char buffer[2048];
    size_t len = sizeof buffer;
    msg_hello hello;
    if (client_hello(&handshake, client->self_id, &hello) != 1 ||
        encode_hello(&hello, buffer, &len) != 1 ||
        io_write_blob(client->fd, buffer, len) != 1)
        goto fail;

    msg_challenge challenge;
    len = sizeof buffer;
    if (io_read_blob(client->fd, buffer, &len) != 1 ||
        decode_challenge(buffer, len, &challenge) != 1 ||
        client_recv_challenge(&handshake, &challenge) != 1)
        goto fail;

    unsigned char k_c2s[AEAD_KEY_BYTE];
    unsigned char k_s2c[AEAD_KEY_BYTE];
    msg_auth auth;
    len = sizeof buffer;
    if (client_auth(&handshake, &auth, k_c2s, k_s2c) != 1 ||
        encode_auth(&auth, buffer, &len) != 1 ||
        io_write_blob(client->fd, buffer, len) != 1)
        goto fail;

    msg_auth_ok auth_ok;
    len = sizeof buffer;
    if (io_read_blob(client->fd, buffer, &len) != 1 ||
        decode_auth_ok(buffer, len, &auth_ok) != 1 ||
        client_recv_auth_ok(&handshake, &auth_ok) != 1) {
        OPENSSL_cleanse(k_c2s, sizeof k_c2s);
        OPENSSL_cleanse(k_s2c, sizeof k_s2c);
        goto fail;
    }

    unsigned char server_id[CLIENT_ID_BYTE] = {0};
    int success = sec_channel_init(&client->channel, 0, k_c2s, k_s2c,
                                   client->self_id, server_id);
    if (success == 1) client->channel_ready = 1;
    OPENSSL_cleanse(k_c2s, sizeof k_c2s);
    OPENSSL_cleanse(k_s2c, sizeof k_s2c);
    hs_ctx_free(&handshake);
    return success;

fail:
    hs_ctx_free(&handshake);
    return 0;
}

static int client_is_running(client_ctx* client) {
    pthread_mutex_lock(&client->lock);
    int running = client->running;
    pthread_mutex_unlock(&client->lock);
    return running;
}

static void client_stop(client_ctx* client) {
    pthread_mutex_lock(&client->lock);
    client->running = 0;
    pthread_mutex_unlock(&client->lock);
    if (client->fd >= 0) shutdown(client->fd, SHUT_RDWR);
}

static int send_packet(client_ctx* client, unsigned char type,
                       const unsigned char* plaintext, size_t plaintext_len) {
    unsigned char packet[PKT_MAX_PLAINTEXT + 256];
    size_t packet_len = sizeof packet;
    if (packet_seal(&client->channel, type, plaintext, plaintext_len,
                    packet, &packet_len) != 1 ||
        io_write_packet(client->fd, packet, packet_len) != 1) {
        client_stop(client);
        return 0;
    }
    return 1;
}

static int process_end(client_ctx* client, const unsigned char* plaintext,
                       size_t plaintext_len) {
    pthread_mutex_lock(&client->lock);
    int has_commit = client->commit_received;
    unsigned char commit[SHA256_BYTE];
    memcpy(commit, client->commit, sizeof commit);
    pthread_mutex_unlock(&client->lock);

    if (!has_commit || plaintext_len != END_PLAINTEXT_BYTE ||
        (plaintext[0] != RESULT_CITIZEN_WIN && plaintext[0] != RESULT_LIAR_WIN) ||
        plaintext[1] >= GAME_MAX_PLAYERS ||
        end_verify(client->server_pub, plaintext, plaintext_len, commit) != 1)
        return 0;

    unsigned char opened[SHA256_BYTE];
    if (commit_hash(plaintext[1], plaintext + 2, opened) != 1 ||
        CRYPTO_memcmp(opened, commit, SHA256_BYTE) != 0)
        return 0;

    const char* result = plaintext[0] == RESULT_CITIZEN_WIN ?
                         "시민 승" : "라이어 승";
    printf("[종료] %s, 라이어=슬롯 %u, 커밋/서명 검증 성공\n",
           result, plaintext[1]);

    pthread_mutex_lock(&client->lock);
    client->completed = 1;
    client->running = 0;
    pthread_mutex_unlock(&client->lock);
    return 1;
}

static void* receive_thread(void* argument) {
    client_ctx* client = argument;
    unsigned char packet[PKT_MAX_PLAINTEXT + 256];
    unsigned char plaintext[PKT_MAX_PLAINTEXT + 1];

    while (client_is_running(client)) {
        size_t packet_len = sizeof packet;
        if (io_read_packet(client->fd, packet, &packet_len) != 1) break;

        unsigned char type;
        size_t plaintext_len = PKT_MAX_PLAINTEXT;
        if (packet_open(&client->channel, packet, packet_len, &type,
                        plaintext, &plaintext_len) != 1) {
            util_log_write(LOG_WARN, "client: 서버 패킷 검증 실패");
            break;
        }
        plaintext[plaintext_len] = '\0';

        switch (type) {
        case MSG_LOBBY:
            if (plaintext_len != LOBBY_PLAINTEXT_BYTE ||
                plaintext[0] > PHASE_END || plaintext[2] >= GAME_MAX_PLAYERS) {
                client_stop(client);
                break;
            }
            pthread_mutex_lock(&client->lock);
            client->my_slot = plaintext[2];
            client->vote_phase = plaintext[0] == PHASE_VOTE;
            if (plaintext[0] != PHASE_HINT) client->my_turn = 0;
            pthread_mutex_unlock(&client->lock);
            printf("[상태] 단계=%u, 접속=%u명, 내 슬롯=%u\n",
                   plaintext[0], plaintext[1], plaintext[2]);
            if (plaintext[0] == PHASE_VOTE)
                printf("[투표] vote N 형식으로 라이어를 지목하세요.\n");
            break;

        case MSG_ASSIGN:
            printf("[제시어] %.*s\n", (int)plaintext_len, (char*)plaintext);
            break;

        case MSG_COMMIT: {
            unsigned char commit[SHA256_BYTE];
            if (commit_verify(client->server_pub, plaintext, plaintext_len,
                              commit) != 1) {
                util_log_write(LOG_ERROR, "client: COMMIT 서버 서명 검증 실패");
                client_stop(client);
                break;
            }
            pthread_mutex_lock(&client->lock);
            if (client->commit_received) {
                pthread_mutex_unlock(&client->lock);
                client_stop(client);
                break;
            }
            memcpy(client->commit, commit, sizeof commit);
            client->commit_received = 1;
            pthread_mutex_unlock(&client->lock);
            printf("[커밋] 서버 서명 검증 성공\n");
            break;
        }

        case MSG_TURN:
            if (plaintext_len != 1 || plaintext[0] >= GAME_MAX_PLAYERS) {
                client_stop(client);
                break;
            }
            pthread_mutex_lock(&client->lock);
            client->my_turn = plaintext[0] == client->my_slot;
            pthread_mutex_unlock(&client->lock);
            printf("[턴] 슬롯 %u 발언 차례%s\n", plaintext[0],
                   plaintext[0] == client->my_slot ? " (본인)" : "");
            break;

        case MSG_HINT:
            if (plaintext_len < 2 || plaintext[0] >= GAME_MAX_PLAYERS) {
                client_stop(client);
                break;
            }
            printf("[발언] 슬롯 %u: %.*s\n", plaintext[0],
                   (int)(plaintext_len - 1), (char*)plaintext + 1);
            break;

        case MSG_END:
            if (process_end(client, plaintext, plaintext_len) != 1) {
                util_log_write(LOG_ERROR, "client: END 서명 또는 커밋 검증 실패");
                printf("[!] 종료 결과 검증 실패\n");
                client_stop(client);
            }
            break;

        case MSG_PKT_ERROR:
            if (plaintext_len != 0) {
                client_stop(client);
                break;
            }
            pthread_mutex_lock(&client->lock);
            int was_pending = client->vote_pending;
            client->vote_pending = 0;   // 거부되었으니 다시 투표할 수 있다
            pthread_mutex_unlock(&client->lock);
            if (was_pending)
                printf("[!] 없는 사람을 지목했습니다. 유효한 슬롯으로 다시 투표하세요.\n");
            else
                printf("[!] 서버가 요청을 거부했습니다.\n");
            break;

        default:
            util_log_write(LOG_WARN, "client: 허용되지 않은 타입 0x%02X", type);
            client_stop(client);
            break;
        }
    }

    pthread_mutex_lock(&client->lock);
    client->running = 0;
    pthread_mutex_unlock(&client->lock);
    return NULL;
}

static void* input_thread(void* argument) {
    client_ctx* client = argument;
    char line[PKT_MAX_PLAINTEXT];
    printf("명령: 내 턴에는 문장 입력, 투표 단계에는 vote N\n");

    while (client_is_running(client)) {
        struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
        int poll_result = poll(&input, 1, 200);
        if (poll_result < 0) break;
        if (poll_result == 0 || !(input.revents & (POLLIN | POLLHUP))) continue;
        if (fgets(line, sizeof line, stdin) == NULL) break;

        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        pthread_mutex_lock(&client->lock);
        int my_turn = client->my_turn;
        int can_vote = client->vote_phase && !client->vote_pending;
        pthread_mutex_unlock(&client->lock);

        if (strncmp(line, "vote ", 5) == 0) {
            char* end = NULL;
            long target = strtol(line + 5, &end, 10);
            if (!can_vote || end == line + 5 || *end != '\0' ||
                target < 0 || target >= GAME_MAX_PLAYERS) {
                printf("[!] 지금 투표할 수 없거나 슬롯 번호가 잘못되었습니다.\n");
                continue;
            }

            unsigned char vote[VOTE_PLAINTEXT_BYTE];
            size_t vote_len = sizeof vote;
            // 보내기 전에 대기 상태로 표시해 두 번 보내지 않는다. 서버가 없는
            // 사람 지목을 거부하면(MSG_PKT_ERROR) 다시 투표할 수 있게 된다.
            pthread_mutex_lock(&client->lock);
            client->vote_pending = 1;
            pthread_mutex_unlock(&client->lock);
            if (vote_build(client->self_key, (unsigned char)target,
                           client->self_id, vote, &vote_len) != 1 ||
                send_packet(client, MSG_VOTE, vote, vote_len) != 1)
                break;
            printf("[투표] 슬롯 %ld 지목 전송\n", target);
        } else {
            if (!my_turn || len >= PKT_MAX_PLAINTEXT) {
                printf("[!] 현재 본인의 발언 차례가 아닙니다.\n");
                continue;
            }
            if (send_packet(client, MSG_HINT, (unsigned char*)line, len) != 1) break;
            pthread_mutex_lock(&client->lock);
            client->my_turn = 0;
            pthread_mutex_unlock(&client->lock);
            printf("[발언] 전송 완료\n");
        }
    }
    return NULL;
}

// 로그는 키 파일과 같은 디렉터리에 client-<공개키 ID>.log 로 만든다.
// 성공 시 1, 버퍼 부족 등 실패 시 0.
static int build_client_log_path(const char* key_path,
                                 const unsigned char id[CLIENT_ID_BYTE],
                                 char* out, size_t out_len) {
    // key_path에서 디렉터리 부분(마지막 '/'까지)을 떼어낸다.
    const char* slash = strrchr(key_path, '/');
    size_t dir_len = slash != NULL ? (size_t)(slash - key_path) + 1 : 0;

    size_t need = dir_len + 7 /*"client-"*/ + CLIENT_ID_BYTE * 2 + 4 /*".log"*/ + 1;
    if (need > out_len) return 0;

    size_t offset = 0;
    if (dir_len > 0) {
        memcpy(out, key_path, dir_len);
        offset = dir_len;
    }
    memcpy(out + offset, "client-", 7);
    offset += 7;
    for (size_t i = 0; i < CLIENT_ID_BYTE; i++) {
        static const char hex[] = "0123456789abcdef";
        out[offset++] = hex[id[i] >> 4];
        out[offset++] = hex[id[i] & 0x0F];
    }
    memcpy(out + offset, ".log", 5);
    return 1;
}

int client_run(const char* host, int port, const char* key_path,
               const unsigned char* password, size_t password_len) {
    if (host == NULL || port <= 0 || port > 65535 || key_path == NULL ||
        password == NULL || password_len == 0)
        return 0;

    int success = 0;
    int receive_started = 0;
    int input_started = 0;
    pthread_t receiver;
    pthread_t input;
    client_ctx client;
    memset(&client, 0, sizeof client);
    client.fd = -1;
    client.my_slot = -1;
    client.running = 1;
    pthread_mutex_init(&client.lock, NULL);

    if (private_key_load_or_create(key_path, password, password_len,
                                   &client.self_key) != 1 ||
        rsa_public_key_id(client.self_key, client.self_id) != 1) {
        fprintf(stderr, "개인키 파일을 만들거나 복호화하지 못했습니다.\n");
        goto done;
    }

    char log_path[256];
    if (build_client_log_path(key_path, client.self_id,
                              log_path, sizeof log_path) != 1 ||
        util_log_init(log_path, LOG_DEBUG) != 1)
        goto done;

    client.fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client.fd < 0) goto done;

    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &address.sin_addr) <= 0 ||
        connect(client.fd, (struct sockaddr*)&address, sizeof address) < 0) {
        util_log_write(LOG_ERROR, "client: 서버 접속 실패");
        goto done;
    }

    client.server_pub = recv_pubkey(client.fd);
    int had_server_pin = server_pin_exists(key_path);
    if (client.server_pub == NULL ||
        (had_server_pin && server_key_pin(key_path, client.server_pub, 0) != 1)) {
        util_log_write(LOG_ERROR, "client: 서버 공개키가 저장된 핀과 불일치");
        goto done;
    }
    if (send_pubkey(client.fd, client.self_key) != 1 ||
        do_client_handshake(&client) != 1 ||
        (!had_server_pin && server_key_pin(key_path, client.server_pub, 1) != 1)) {
        util_log_write(LOG_ERROR, "client: 공개키 교환 또는 핸드셰이크 실패");
        goto done;
    }
    util_log_write(LOG_INFO, "client: 보안 채널 수립 성공");
    printf("[접속] 서버와 보안 채널 수립 완료\n");

    if (send_packet(&client, MSG_READY, NULL, 0) != 1) goto done;
    printf("[준비] READY 전송\n");

    if (pthread_create(&receiver, NULL, receive_thread, &client) != 0) goto done;
    receive_started = 1;
    if (pthread_create(&input, NULL, input_thread, &client) != 0) {
        client_stop(&client);
        goto done;
    }
    input_started = 1;

    pthread_join(receiver, NULL);
    receive_started = 0;
    client_stop(&client);
    pthread_join(input, NULL);
    input_started = 0;
    success = client.completed;

done:
    client_stop(&client);
    if (receive_started) pthread_join(receiver, NULL);
    if (input_started) pthread_join(input, NULL);
    if (client.fd >= 0) close(client.fd);
    if (client.server_pub != NULL) EVP_PKEY_free(client.server_pub);
    if (client.self_key != NULL) EVP_PKEY_free(client.self_key);
    if (client.channel_ready) sec_channel_free(&client.channel);
    pthread_mutex_destroy(&client.lock);
    util_log_close();
    return success;
}
