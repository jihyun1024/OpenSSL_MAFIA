#define _POSIX_C_SOURCE 200809L
#include "game.h"
#include "protocol.h"
#include "util.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "[실패] %s\n", message); \
            goto done; \
        } \
    } while (0)

static int demonstrate_packet_defenses(void) {
    unsigned char k_c2s[AEAD_KEY_BYTE];
    unsigned char k_s2c[AEAD_KEY_BYTE];
    unsigned char client_id[CLIENT_ID_BYTE];
    unsigned char server_id[CLIENT_ID_BYTE] = {0};
    if (rand_bytes(k_c2s, sizeof k_c2s) != 1 ||
        rand_bytes(k_s2c, sizeof k_s2c) != 1 ||
        rand_bytes(client_id, sizeof client_id) != 1)
        return 0;

    sec_channel client;
    sec_channel server;
    if (sec_channel_init(&client, 0, k_c2s, k_s2c, client_id, server_id) != 1 ||
        sec_channel_init(&server, 1, k_c2s, k_s2c, server_id, client_id) != 1)
        return 0;

    unsigned char packet[512];
    size_t packet_len = sizeof packet;
    const unsigned char hint[] = "동물과 관련 있습니다";
    if (packet_seal(&client, MSG_HINT, hint, sizeof hint - 1,
                    packet, &packet_len) != 1)
        return 0;

    unsigned char plaintext[128];
    unsigned char type;
    size_t plaintext_len = sizeof plaintext;
    if (packet_open(&server, packet, packet_len, &type,
                    plaintext, &plaintext_len) != 1 ||
        type != MSG_HINT || plaintext_len != sizeof hint - 1 ||
        memcmp(plaintext, hint, plaintext_len) != 0)
        return 0;

    plaintext_len = sizeof plaintext;
    if (packet_open(&server, packet, packet_len, &type,
                    plaintext, &plaintext_len) != 0)
        return 0;
    puts("[통과] 캡처 패킷 재전송을 seq 검사로 거부");

    packet_len = sizeof packet;
    if (packet_seal(&client, MSG_HINT, hint, sizeof hint - 1,
                    packet, &packet_len) != 1)
        return 0;
    packet[PKT_LEN_BYTE + PKT_HEADER_BYTE] ^= 1;
    plaintext_len = sizeof plaintext;
    if (packet_open(&server, packet, packet_len, &type,
                    plaintext, &plaintext_len) != 0)
        return 0;
    puts("[통과] 암호문 1비트 변조를 GCM 태그 검사로 거부");

    packet_len = sizeof packet;
    if (packet_seal(&client, MSG_HINT, hint, sizeof hint - 1,
                    packet, &packet_len) != 1)
        return 0;
    packet[PKT_LEN_BYTE] = MSG_VOTE;
    plaintext_len = sizeof plaintext;
    if (packet_open(&server, packet, packet_len, &type,
                    plaintext, &plaintext_len) != 0)
        return 0;
    puts("[통과] type 헤더 변조를 AAD/GCM 태그 검사로 거부");

    sec_channel_free(&client);
    sec_channel_free(&server);
    OPENSSL_cleanse(k_c2s, sizeof k_c2s);
    OPENSSL_cleanse(k_s2c, sizeof k_s2c);
    return 1;
}

static int demonstrate_signature_defense(void) {
    int success = 0;
    EVP_PKEY* voter = rsa_generate_key();
    EVP_PKEY* attacker = rsa_generate_key();
    if (voter == NULL || attacker == NULL) goto done;

    unsigned char voter_id[CLIENT_ID_BYTE];
    if (rsa_public_key_id(voter, voter_id) != 1) goto done;

    unsigned char vote[VOTE_PLAINTEXT_BYTE];
    unsigned char target = 0;
    size_t vote_len = sizeof vote;
    if (vote_build(attacker, 2, voter_id, vote, &vote_len) != 1 ||
        vote_verify(voter, voter_id, vote, vote_len, NULL) != 0)
        goto done;

    game_state game;
    game_init(&game);
    int slot;
    if (game_add_player(&game, voter_id, &slot) != 1) goto done;
    for (int i = 1; i < GAME_MIN_PLAYERS; i++) {
        unsigned char id[GAME_ID_BYTE] = {0};
        id[0] = (unsigned char)i;
        if (game_add_player(&game, id, &slot) != 1) goto done;
    }
    game.phase = PHASE_VOTE;
    if (vote_verify(voter, voter_id, vote, vote_len, &target) == 1)
        game_submit_vote(&game, 0, target);
    if (game.players[0].voted) goto done;
    puts("[통과] 다른 키로 만든 위조 투표 서명을 거부하고 표를 미반영");

    vote_len = sizeof vote;
    target = 0;
    if (vote_build(voter, 2, voter_id, vote, &vote_len) != 1 ||
        vote_verify(voter, voter_id, vote, vote_len, &target) != 1 || target != 2)
        goto done;
    puts("[통과] 등록된 키의 정상 투표 서명을 수용");
    success = 1;

done:
    EVP_PKEY_free(voter);
    EVP_PKEY_free(attacker);
    return success;
}

static int setup_hint_game(game_state* game, int liar) {
    game_init(game);
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        unsigned char id[GAME_ID_BYTE] = {0};
        id[0] = (unsigned char)(i + 1);
        int slot;
        if (game_add_player(game, id, &slot) != 1 || slot != i) return 0;
    }
    game->liar_index = liar;
    game->phase = PHASE_ASSIGN;
    return game_start_hints(game);
}

static int demonstrate_game_rules(void) {
    game_state game;
    if (setup_hint_game(&game, 2) != 1) return 0;

    for (int turn = 0; turn < GAME_MAX_PLAYERS * HINT_ROUNDS; turn++) {
        int expected = turn % GAME_MAX_PLAYERS;
        if (game_current_speaker(&game) != expected ||
            game_submit_hint(&game, (expected + 1) % GAME_MAX_PLAYERS) != 0 ||
            game_submit_hint(&game, expected) != 1)
            return 0;
    }
    if (game.phase != PHASE_VOTE || game_submit_hint(&game, 0) != 0) return 0;
    puts("[통과] 접속 순서대로 2바퀴만 발언하도록 강제");

    if (game_submit_vote(&game, 0, 2) != 1 ||
        game_submit_vote(&game, 1, 2) != 1 ||
        game_submit_vote(&game, 2, 0) != 1 ||
        game_submit_vote(&game, 3, 2) != 1 ||
        game_judge(&game) != RESULT_CITIZEN_WIN)
        return 0;
    puts("[통과] 단독 최다 득표 라이어 지목 시 시민 승");

    if (setup_hint_game(&game, 2) != 1) return 0;
    for (int turn = 0; turn < GAME_MAX_PLAYERS * HINT_ROUNDS; turn++)
        if (game_submit_hint(&game, turn % GAME_MAX_PLAYERS) != 1) return 0;
    if (game_submit_vote(&game, 0, 2) != 1 ||
        game_submit_vote(&game, 1, 2) != 1 ||
        game_submit_vote(&game, 2, 1) != 1 ||
        game_submit_vote(&game, 3, 1) != 1 ||
        game_judge(&game) != RESULT_LIAR_WIN)
        return 0;
    puts("[통과] 최다 득표 동점 시 재투표 없이 라이어 승");

    if (setup_hint_game(&game, 2) != 1) return 0;
    for (int turn = 0; turn < GAME_MAX_PLAYERS * HINT_ROUNDS; turn++)
        if (game_timeout_hint(&game) != 1) return 0;
    if (game.phase != PHASE_VOTE) return 0;
    puts("[통과] 발언 시간 초과를 상태기계에 반영");

    // 3인 게임에서 존재하지 않는 슬롯 3을 지목하면 거부되지만 투표권은 유지되어
    // 유효한 슬롯으로 다시 투표할 수 있어야 한다.
    game_init(&game);
    for (int i = 0; i < GAME_MIN_PLAYERS; i++) {
        unsigned char id[GAME_ID_BYTE] = {0};
        id[0] = (unsigned char)(i + 1);
        int slot;
        if (game_add_player(&game, id, &slot) != 1) return 0;
    }
    game.liar_index = 1;
    game.phase = PHASE_VOTE;
    if (game_submit_vote(&game, 0, 3) != 0 || game.players[0].voted != 0)
        return 0;
    if (game_submit_vote(&game, 0, 1) != 1 || game.players[0].voted != 1)
        return 0;
    if (game_submit_vote(&game, 0, 2) != 0)   // 집계 전 재투표는 중복으로 거부
        return 0;
    puts("[통과] 없는 사람 지목은 거부하되 투표권을 유지");
    return 1;
}

static int demonstrate_commit_opening(void) {
    int success = 0;
    EVP_PKEY* server = rsa_generate_key();
    if (server == NULL) return 0;

    unsigned char nonce[COMMIT_NONCE_BYTE];
    unsigned char hash[SHA256_BYTE];
    unsigned char received_hash[SHA256_BYTE];
    unsigned char commit[COMMIT_PLAINTEXT_BYTE];
    unsigned char end[END_PLAINTEXT_BYTE];
    if (rand_bytes(nonce, sizeof nonce) != 1 || commit_hash(2, nonce, hash) != 1 ||
        commit_build(server, hash, commit) != 1 ||
        commit_verify(server, commit, sizeof commit, received_hash) != 1 ||
        CRYPTO_memcmp(hash, received_hash, sizeof hash) != 0 ||
        end_build(server, RESULT_CITIZEN_WIN, 2, nonce, hash, end) != 1 ||
        end_verify(server, end, sizeof end, received_hash) != 1)
        goto done;

    unsigned char opened[SHA256_BYTE];
    if (commit_hash(end[1], end + 2, opened) != 1 ||
        CRYPTO_memcmp(opened, received_hash, sizeof opened) != 0)
        goto done;
    puts("[통과] END 공개값으로 최초 라이어 커밋과 서버 서명을 검증");

    end[2] ^= 1;
    if (end_verify(server, end, sizeof end, received_hash) != 0) goto done;
    puts("[통과] 변조된 커밋 공개값의 서버 서명을 거부");
    success = 1;

done:
    EVP_PKEY_free(server);
    return success;
}

static int demonstrate_auth_binding(void) {
    int success = 0;
    EVP_PKEY* client_key = rsa_generate_key();
    EVP_PKEY* server_key = rsa_generate_key();
    handshake_ctx client;
    handshake_ctx server;
    memset(&client, 0, sizeof client);
    memset(&server, 0, sizeof server);
    if (client_key == NULL || server_key == NULL ||
        hs_ctx_init(&client, client_key, server_key) != 1 ||
        hs_ctx_init(&server, server_key, client_key) != 1)
        goto done;

    unsigned char client_id[CLIENT_ID_BYTE];
    msg_hello hello;
    msg_challenge challenge;
    msg_auth auth;
    unsigned char client_c2s[AEAD_KEY_BYTE];
    unsigned char client_s2c[AEAD_KEY_BYTE];
    unsigned char server_c2s[AEAD_KEY_BYTE];
    unsigned char server_s2c[AEAD_KEY_BYTE];
    if (rsa_public_key_id(client_key, client_id) != 1 ||
        client_hello(&client, client_id, &hello) != 1 ||
        server_recv_hello(&server, &hello) != 1 ||
        server_challenge(&server, &challenge) != 1 ||
        client_recv_challenge(&client, &challenge) != 1 ||
        client_auth(&client, &auth, client_c2s, client_s2c) != 1)
        goto done;

    auth.enc_keys[0] ^= 1;
    if (server_recv_auth(&server, &auth, server_c2s, server_s2c) != 0)
        goto done;
    puts("[통과] AUTH의 OAEP 세션키 암호문 바꿔치기를 서명으로 거부");
    success = 1;

done:
    hs_ctx_free(&client);
    hs_ctx_free(&server);
    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_key);
    return success;
}

static int demonstrate_key_storage(void) {
    char path[] = "/tmp/liar-key-test-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    close(fd);
    unlink(path);

    const unsigned char password[] = "correct test password";
    const unsigned char wrong_password[] = "wrong test password";
    EVP_PKEY* created = NULL;
    EVP_PKEY* loaded = NULL;
    EVP_PKEY* rejected = NULL;
    unsigned char created_id[GAME_ID_BYTE];
    unsigned char loaded_id[GAME_ID_BYTE];
    int success = private_key_load_or_create(path, password, sizeof password - 1,
                                             &created) == 1 &&
                  private_key_load_or_create(path, password, sizeof password - 1,
                                             &loaded) == 1 &&
                  rsa_public_key_id(created, created_id) == 1 &&
                  rsa_public_key_id(loaded, loaded_id) == 1 &&
                  CRYPTO_memcmp(created_id, loaded_id, sizeof created_id) == 0 &&
                  private_key_load_or_create(path, wrong_password,
                                             sizeof wrong_password - 1,
                                             &rejected) == 0;
    if (success) puts("[통과] PBKDF2/AES-GCM 개인키 저장과 잘못된 암호 거부");

    EVP_PKEY_free(created);
    EVP_PKEY_free(loaded);
    EVP_PKEY_free(rejected);
    unlink(path);
    return success;
}

int main(void) {
    int success = 0;
    util_log_init(NULL, LOG_ERROR);
    CHECK(demonstrate_packet_defenses(), "재전송/변조 방어");
    CHECK(demonstrate_signature_defense(), "투표 위조 방어");
    CHECK(demonstrate_game_rules(), "게임 규칙");
    CHECK(demonstrate_commit_opening(), "커밋 공개 검증");
    CHECK(demonstrate_auth_binding(), "AUTH 세션키 결박");
    CHECK(demonstrate_key_storage(), "암호화 개인키 저장");
    success = 1;

done:
    util_log_close();
    return success ? 0 : 1;
}
