#define _POSIX_C_SOURCE 200809L
#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/x509.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MAX_PROTOCOL_FAILURES 3
#define HANDSHAKE_TIMEOUT_SEC 15
#define GAME_SEND_TIMEOUT_SEC 5

// 게임 상태와 연결별 채널 송신 순서를 이 락 하나로 보호한다.
static game_state g_game;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static EVP_PKEY* g_server_key = NULL;
static const char* g_words_dir = NULL;

typedef struct {
    int fd;
    int index;
    sec_channel ch;
    EVP_PKEY* peer_pub;
    unsigned char id[CLIENT_ID_BYTE];
    int channel_ready;
    int alive;
    int failures;
} conn_ctx;

static conn_ctx g_conns[GAME_MAX_PLAYERS];
static int g_conn_count = 0;

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

static int do_server_handshake(conn_ctx* connection) {
    handshake_ctx handshake;
    if (hs_ctx_init(&handshake, g_server_key, connection->peer_pub) != 1) return 0;

    unsigned char buffer[2048];
    size_t len = sizeof buffer;
    msg_hello hello;
    if (io_read_blob(connection->fd, buffer, &len) != 1 ||
        decode_hello(buffer, len, &hello) != 1 ||
        server_recv_hello(&handshake, &hello) != 1)
        goto fail;

    // 클라이언트 ID를 공개키에 결박해 다른 ID를 사칭하지 못하게 한다.
    unsigned char expected_id[CLIENT_ID_BYTE];
    if (rsa_public_key_id(connection->peer_pub, expected_id) != 1 ||
        CRYPTO_memcmp(expected_id, handshake.client_id, CLIENT_ID_BYTE) != 0) {
        util_log_write(LOG_WARN, "server: 공개키와 client_id 불일치");
        goto fail;
    }

    msg_challenge challenge;
    len = sizeof buffer;
    if (server_challenge(&handshake, &challenge) != 1 ||
        encode_challenge(&challenge, buffer, &len) != 1 ||
        io_write_blob(connection->fd, buffer, len) != 1)
        goto fail;

    unsigned char k_c2s[AEAD_KEY_BYTE];
    unsigned char k_s2c[AEAD_KEY_BYTE];
    msg_auth auth;
    len = sizeof buffer;
    if (io_read_blob(connection->fd, buffer, &len) != 1 ||
        decode_auth(buffer, len, &auth) != 1 ||
        server_recv_auth(&handshake, &auth, k_c2s, k_s2c) != 1)
        goto fail;

    msg_auth_ok auth_ok;
    len = sizeof buffer;
    if (server_auth_ok(&handshake, &auth_ok) != 1 ||
        encode_auth_ok(&auth_ok, buffer, &len) != 1 ||
        io_write_blob(connection->fd, buffer, len) != 1) {
        OPENSSL_cleanse(k_c2s, sizeof k_c2s);
        OPENSSL_cleanse(k_s2c, sizeof k_s2c);
        goto fail;
    }

    unsigned char server_id[CLIENT_ID_BYTE] = {0};
    int success = sec_channel_init(&connection->ch, 1, k_c2s, k_s2c,
                                   server_id, handshake.client_id);
    OPENSSL_cleanse(k_c2s, sizeof k_c2s);
    OPENSSL_cleanse(k_s2c, sizeof k_s2c);
    if (success != 1) goto fail;

    memcpy(connection->id, handshake.client_id, CLIENT_ID_BYTE);
    connection->channel_ready = 1;
    hs_ctx_free(&handshake);
    return 1;

fail:
    hs_ctx_free(&handshake);
    return 0;
}

// 호출자는 g_lock을 보유해야 한다. 이 규칙으로 채널별 tx_seq도 직렬화한다.
static int send_packet_locked(conn_ctx* connection, unsigned char type,
                              const unsigned char* plaintext, size_t plaintext_len) {
    if (connection == NULL || !connection->alive || !connection->channel_ready) return 0;
    unsigned char packet[PKT_MAX_PLAINTEXT + 256];
    size_t packet_len = sizeof packet;
    if (packet_seal(&connection->ch, type, plaintext, plaintext_len,
                    packet, &packet_len) != 1 ||
        io_write_packet(connection->fd, packet, packet_len) != 1) {
        connection->alive = 0;
        shutdown(connection->fd, SHUT_RDWR);
        pthread_cond_broadcast(&g_cond);
        return 0;
    }
    return 1;
}

static void broadcast_locked(unsigned char type, const unsigned char* plaintext,
                             size_t plaintext_len) {
    for (int i = 0; i < g_conn_count; i++)
        if (g_conns[i].alive)
            send_packet_locked(&g_conns[i], type, plaintext, plaintext_len);
}

static void send_lobby_status_locked(void) {
    for (int i = 0; i < g_conn_count; i++) {
        unsigned char status[LOBBY_PLAINTEXT_BYTE] = {
            (unsigned char)g_game.phase,
            (unsigned char)g_game.player_count,
            (unsigned char)g_conns[i].index
        };
        if (g_conns[i].alive)
            send_packet_locked(&g_conns[i], MSG_LOBBY, status, sizeof status);
    }
}

static int any_connection_dead_locked(void) {
    for (int i = 0; i < g_conn_count; i++)
        if (!g_conns[i].alive) return 1;
    return 0;
}

static struct timespec deadline_after(int seconds) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += seconds;
    return deadline;
}

static int run_game_master(void) {
    int success = 0;
    pthread_mutex_lock(&g_lock);

    while (!game_all_ready(&g_game)) {
        if (any_connection_dead_locked()) {
            util_log_write(LOG_ERROR, "server: 로비에서 연결 종료, 게임 취소");
            goto done;
        }
        pthread_cond_wait(&g_cond, &g_lock);
    }

    if (game_assign(&g_game, g_words_dir) != 1) {
        util_log_write(LOG_ERROR, "server: 카테고리 또는 제시어 배정 실패");
        goto done;
    }
    send_lobby_status_locked();

    for (int i = 0; i < g_conn_count; i++) {
        char assignment[WORD_MAX_BYTE + CATEGORY_MAX_BYTE + 2];
        if (game_word_for(&g_game, g_conns[i].index,
                          assignment, sizeof assignment) != 1 ||
            send_packet_locked(&g_conns[i], MSG_ASSIGN,
                               (unsigned char*)assignment, strlen(assignment)) != 1)
            goto done;
    }

    unsigned char commit[COMMIT_PLAINTEXT_BYTE];
    if (commit_build(g_server_key, g_game.commit_hash_val, commit) != 1) {
        util_log_write(LOG_ERROR, "server: COMMIT 서명 실패");
        goto done;
    }
    broadcast_locked(MSG_COMMIT, commit, sizeof commit);

    if (game_start_hints(&g_game) != 1) goto done;
    send_lobby_status_locked();

    while (g_game.phase == PHASE_HINT) {
        int speaker = game_current_speaker(&g_game);
        if (speaker < 0) break;

        unsigned char turn = (unsigned char)speaker;
        broadcast_locked(MSG_TURN, &turn, 1);
        int before = g_game.hint_total;
        struct timespec deadline = deadline_after(HINT_TIMEOUT_SEC);
        while (g_game.phase == PHASE_HINT && g_game.hint_total == before) {
            int wait_result = pthread_cond_timedwait(&g_cond, &g_lock, &deadline);
            if (wait_result == ETIMEDOUT) {
                game_timeout_hint(&g_game);
                break;
            }
        }
    }

    if (g_game.phase != PHASE_VOTE) goto done;
    send_lobby_status_locked();

    // 투표에는 제한 시간을 두지 않는다. 전원이 투표를 마칠 때까지 기다리되,
    // 투표 중 연결이 끊기면 더는 집계가 완료될 수 없으므로 게임을 중단한다.
    while (g_game.phase == PHASE_VOTE) {
        if (any_connection_dead_locked()) {
            util_log_write(LOG_WARN, "server: 투표 중 연결 종료, 게임 중단");
            goto done;
        }
        pthread_cond_wait(&g_cond, &g_lock);
    }

    game_result result = game_judge(&g_game);
    if (result == RESULT_NONE) goto done;

    unsigned char end[END_PLAINTEXT_BYTE];
    if (end_build(g_server_key, (unsigned char)result,
                  (unsigned char)g_game.liar_index, g_game.commit_nonce,
                  g_game.commit_hash_val, end) != 1) {
        util_log_write(LOG_ERROR, "server: END 서명 실패");
        goto done;
    }
    broadcast_locked(MSG_END, end, sizeof end);
    util_log_write(LOG_INFO, "server: 게임 종료 결과=%d", (int)result);
    success = 1;

done:
    pthread_mutex_unlock(&g_lock);
    return success;
}

static void protocol_failure_locked(conn_ctx* connection, const char* reason) {
    connection->failures++;
    util_log_write(LOG_WARN, "server: 슬롯 %d 요청 거부 (%s, 연속 %d회)",
                   connection->index, reason, connection->failures);
    send_packet_locked(connection, MSG_PKT_ERROR, NULL, 0);
    if (connection->failures >= MAX_PROTOCOL_FAILURES) {
        util_log_write(LOG_WARN, "server: 슬롯 %d 연속 오류로 연결 종료",
                       connection->index);
        connection->alive = 0;
        shutdown(connection->fd, SHUT_RDWR);
    }
}

static void* player_thread(void* argument) {
    conn_ctx* connection = argument;
    unsigned char packet[PKT_MAX_PLAINTEXT + 256];
    unsigned char plaintext[PKT_MAX_PLAINTEXT];

    for (;;) {
        size_t packet_len = sizeof packet;
        if (io_read_packet(connection->fd, packet, &packet_len) != 1) break;

        unsigned char type;
        size_t plaintext_len = sizeof plaintext;
        if (packet_open(&connection->ch, packet, packet_len, &type,
                        plaintext, &plaintext_len) != 1) {
            pthread_mutex_lock(&g_lock);
            protocol_failure_locked(connection, "패킷 검증 실패");
            pthread_mutex_unlock(&g_lock);
            continue;
        }

        pthread_mutex_lock(&g_lock);
        int accepted = 0;
        switch (type) {
        case MSG_READY:
            if (plaintext_len == 0)
                accepted = game_set_ready(&g_game, connection->index);
            if (accepted) send_lobby_status_locked();
            break;

        case MSG_HINT:
            if (plaintext_len > 0 && plaintext_len < PKT_MAX_PLAINTEXT &&
                game_submit_hint(&g_game, connection->index) == 1) {
                unsigned char relay[PKT_MAX_PLAINTEXT];
                relay[0] = (unsigned char)connection->index;
                memcpy(relay + 1, plaintext, plaintext_len);
                broadcast_locked(MSG_HINT, relay, plaintext_len + 1);
                accepted = 1;
            }
            break;

        case MSG_VOTE: {
            unsigned char target;
            if (vote_verify(connection->peer_pub, connection->id,
                            plaintext, plaintext_len, &target) == 1)
                accepted = game_submit_vote(&g_game, connection->index, target);
            break;
        }

        default:
            break;
        }

        if (accepted)
            connection->failures = 0;
        else
            protocol_failure_locked(connection, "타입, 길이 또는 게임 상태 불일치");
        pthread_cond_broadcast(&g_cond);
        pthread_mutex_unlock(&g_lock);
    }

    pthread_mutex_lock(&g_lock);
    connection->alive = 0;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);
    util_log_write(LOG_INFO, "server: 슬롯 %d 연결 종료", connection->index);
    return NULL;
}

int server_run(int port, const char* words_dir, int expected_players,
               const char* key_path,
               const unsigned char* password, size_t password_len) {
    if (port <= 0 || port > 65535 || words_dir == NULL || key_path == NULL ||
        password == NULL || password_len == 0 ||
        expected_players < GAME_MIN_PLAYERS || expected_players > GAME_MAX_PLAYERS)
        return 0;

    int success = 0;
    int server_fd = -1;
    pthread_t threads[GAME_MAX_PLAYERS];
    memset(g_conns, 0, sizeof g_conns);
    g_conn_count = 0;
    g_words_dir = words_dir;
    game_init(&g_game);

    if (private_key_load_or_create(key_path, password, password_len,
                                   &g_server_key) != 1) {
        util_log_write(LOG_ERROR, "server: 암호화된 RSA 키를 열지 못함");
        goto done;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) goto done;
    int option = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof option);

    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((unsigned short)port);
    if (bind(server_fd, (struct sockaddr*)&address, sizeof address) < 0 ||
        listen(server_fd, GAME_MAX_PLAYERS) < 0) {
        util_log_write(LOG_ERROR, "server: 포트 %d bind/listen 실패", port);
        goto done;
    }
    util_log_write(LOG_INFO, "server: 포트 %d에서 %d명 접속 대기", port,
                   expected_players);

    while (g_conn_count < expected_players) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            goto done;
        }

        conn_ctx* connection = &g_conns[g_conn_count];
        memset(connection, 0, sizeof *connection);
        connection->fd = client_fd;
        connection->index = -1;
        connection->alive = 1;

        if (send_pubkey(client_fd, g_server_key) != 1 ||
            (connection->peer_pub = recv_pubkey(client_fd)) == NULL ||
            do_server_handshake(connection) != 1) {
            util_log_write(LOG_WARN, "server: 키 교환 또는 핸드셰이크 실패");
            EVP_PKEY_free(connection->peer_pub);
            connection->peer_pub = NULL;
            close(client_fd);
            continue;
        }

        pthread_mutex_lock(&g_lock);
        int added = game_add_player(&g_game, connection->id, &connection->index);
        int thread_created = 0;
        if (added) {
            int thread_index = g_conn_count++;
            if (pthread_create(&threads[thread_index], NULL,
                               player_thread, connection) == 0) {
                thread_created = 1;
            } else {
                g_conn_count--;
                game_remove_player(&g_game, connection->index);
            }
        }
        pthread_mutex_unlock(&g_lock);

        if (!added || !thread_created) {
            util_log_write(LOG_WARN, !added ?
                           "server: 중복 ID 또는 정원 초과 연결 거부" :
                           "server: 플레이어 스레드 생성 실패");
            sec_channel_free(&connection->ch);
            EVP_PKEY_free(connection->peer_pub);
            close(client_fd);
            continue;
        }
        util_log_write(LOG_INFO, "server: 슬롯 %d 핸드셰이크 성공", connection->index);
    }

    pthread_mutex_lock(&g_lock);
    send_lobby_status_locked();
    pthread_mutex_unlock(&g_lock);
    success = run_game_master();

done:
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_conn_count; i++) {
        g_conns[i].alive = 0;
        shutdown(g_conns[i].fd, SHUT_RDWR);
    }
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);

    for (int i = 0; i < g_conn_count; i++) {
        pthread_join(threads[i], NULL);
        close(g_conns[i].fd);
        EVP_PKEY_free(g_conns[i].peer_pub);
        if (g_conns[i].channel_ready) sec_channel_free(&g_conns[i].ch);
    }
    if (server_fd >= 0) close(server_fd);
    EVP_PKEY_free(g_server_key);
    g_server_key = NULL;
    return success;
}
