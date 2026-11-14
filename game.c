#include "game.h"

#include <string.h>
#include <stdio.h>
#include <dirent.h>

// [0, n) 범위의 균일 난수. rand_bytes 기반(modulo 편향은 게임 용도상 무시).
static int rand_below(int n) {
    if (n <= 0) return 0;
    unsigned int r = 0;
    if (rand_bytes((unsigned char*)&r, sizeof r) != 1) return 0;
    return (int)(r % (unsigned int)n);
}

// 슬롯 번호 유효성
static int valid_index(const game_state* gs, int index) {
    return gs != NULL && index >= 0 && index < GAME_MAX_PLAYERS &&
           gs->players[index].in_use;
}

void game_init(game_state* gs) {
    if (gs == NULL) return;
    memset(gs, 0, sizeof *gs);
    gs->phase = PHASE_LOBBY;
    gs->liar_index = -1;
    gs->turn_cursor = 0;
    gs->result = RESULT_NONE;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        gs->players[i].vote_target = -1;
    }
}

int game_add_player(game_state* gs, const unsigned char id[GAME_ID_BYTE], int* out_index) {
    if (gs == NULL || id == NULL || out_index == NULL) return 0;
    if (gs->phase != PHASE_LOBBY) return 0;
    if (gs->player_count >= GAME_MAX_PLAYERS) return 0;

    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (!gs->players[i].in_use) {
            player_slot* p = &gs->players[i];
            memset(p, 0, sizeof *p);
            memcpy(p->id, id, GAME_ID_BYTE);
            p->in_use = 1;
            p->vote_target = -1;
            gs->turn_order[gs->player_count] = i;   // 접속 순서 기록
            gs->player_count++;
            *out_index = i;
            util_log_write(LOG_INFO, "game: 플레이어 슬롯 %d 추가 (현재 %d명)",
                           i, gs->player_count);
            return 1;
        }
    }
    return 0;
}

int game_set_ready(game_state* gs, int index) {
    if (!valid_index(gs, index)) return 0;
    gs->players[index].ready = 1;
    util_log_write(LOG_INFO, "game: 슬롯 %d READY", index);
    return 1;
}

int game_all_ready(const game_state* gs) {
    if (gs == NULL) return 0;
    if (gs->player_count < GAME_MIN_PLAYERS) return 0;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use && !gs->players[i].ready) return 0;
    }
    return 1;
}

// 디렉터리에서 .txt 카테고리 파일을 세어 i번째 파일명을 고른다.
static int pick_category_file(const char* dir_path, char* name_out, size_t name_len) {
    DIR* d = opendir(dir_path);
    if (d == NULL) return 0;

    char names[64][CATEGORY_MAX_BYTE];
    int count = 0;
    struct dirent* e;
    while ((e = readdir(d)) != NULL && count < 64) {
        const char* dot = strrchr(e->d_name, '.');
        if (dot != NULL && strcmp(dot, ".txt") == 0) {
            snprintf(names[count], CATEGORY_MAX_BYTE, "%s", e->d_name);
            count++;
        }
    }
    closedir(d);
    if (count == 0) return 0;

    int pick = rand_below(count);
    snprintf(name_out, name_len, "%s", names[pick]);
    return 1;
}

// 파일에서 랜덤 라인 하나를 제시어로 고른다 (개행 제거).
static int pick_word_from_file(const char* path, char* word_out, size_t word_len) {
    FILE* fp = fopen(path, "r");
    if (fp == NULL) return 0;

    char line[WORD_MAX_BYTE];
    char chosen[WORD_MAX_BYTE];
    int n = 0;
    chosen[0] = '\0';

    // 저수지 샘플링: 메모리 적게 쓰며 균일 선택
    while (fgets(line, sizeof line, fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        n++;
        if (rand_below(n) == 0) snprintf(chosen, sizeof chosen, "%s", line);
    }
    fclose(fp);
    if (n == 0 || chosen[0] == '\0') return 0;

    snprintf(word_out, word_len, "%s", chosen);
    return 1;
}

int game_assign(game_state* gs, const char* dir_path) {
    if (gs == NULL || dir_path == NULL) return 0;
    if (gs->phase != PHASE_LOBBY) return 0;
    if (!game_all_ready(gs)) return 0;

    // 카테고리 파일 선택
    char fname[CATEGORY_MAX_BYTE];
    if (!pick_category_file(dir_path, fname, sizeof fname)) return 0;

    // 카테고리명 = 파일명에서 ".txt" 제거
    snprintf(gs->category, sizeof gs->category, "%s", fname);
    char* dot = strrchr(gs->category, '.');
    if (dot != NULL) *dot = '\0';

    // 제시어 선택
    char path[256];
    snprintf(path, sizeof path, "%s/%s", dir_path, fname);
    if (!pick_word_from_file(path, gs->word, sizeof gs->word)) return 0;

    // 라이어를 접속자 중 랜덤 지정
    int order_pick = rand_below(gs->player_count);
    gs->liar_index = gs->turn_order[order_pick];

    // 공정성 커밋: hash(liar_id || nonce)
    if (rand_bytes(gs->commit_nonce, COMMIT_NONCE_BYTE) != 1) return 0;
    if (commit_hash(gs->players[gs->liar_index].id, (unsigned char)gs->liar_index,
                    gs->commit_nonce, gs->commit_hash_val) != 1) return 0;

    gs->phase = PHASE_ASSIGN;
    util_log_write(LOG_INFO, "game: ASSIGN 카테고리=%s 라이어슬롯=%d",
                   gs->category, gs->liar_index);
    return 1;
}

int game_word_for(const game_state* gs, int index, char* buf, size_t buf_len) {
    if (!valid_index(gs, index) || buf == NULL) return 0;
    if (gs->phase != PHASE_ASSIGN && gs->phase != PHASE_HINT) return 0;

    if (index == gs->liar_index) {
        // 라이어: 카테고리만
        snprintf(buf, buf_len, "%s|", gs->category);
    } else {
        // 시민: 카테고리 + 제시어
        snprintf(buf, buf_len, "%s|%s", gs->category, gs->word);
    }
    return 1;
}

int game_start_hints(game_state* gs) {
    if (gs == NULL || gs->phase != PHASE_ASSIGN) return 0;
    gs->phase = PHASE_HINT;
    gs->turn_cursor = 0;
    gs->hint_total = 0;
    util_log_write(LOG_INFO, "game: HINT 페이즈 시작");
    return 1;
}

int game_current_speaker(const game_state* gs) {
    if (gs == NULL || gs->phase != PHASE_HINT) return -1;
    int total_turns = gs->player_count * HINT_ROUNDS;
    if (gs->hint_total >= total_turns) return -1;
    // 라운드 로빈: cursor를 player_count로 나눈 나머지 순서
    return gs->turn_order[gs->turn_cursor % gs->player_count];
}

int game_submit_hint(game_state* gs, int index) {
    if (gs == NULL || gs->phase != PHASE_HINT) return 0;
    int speaker = game_current_speaker(gs);
    if (speaker < 0 || speaker != index) return 0;           // 턴 아님
    if (gs->players[index].hints_used >= HINT_ROUNDS) return 0;

    gs->players[index].hints_used++;
    gs->hint_total++;
    gs->turn_cursor++;
    util_log_write(LOG_INFO, "game: 슬롯 %d 발언 (%d/%d)",
                   index, gs->players[index].hints_used, HINT_ROUNDS);

    if (game_current_speaker(gs) < 0) {
        gs->phase = PHASE_VOTE;
        util_log_write(LOG_INFO, "game: 발언 종료, VOTE 페이즈 전이");
    }
    return 1;
}

// 전원 투표 완료 시 집계하여 판정하고 END로 전이.
static void tally_and_judge(game_state* gs) {
    int votes[GAME_MAX_PLAYERS] = {0};
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use && gs->players[i].voted) {
            int t = gs->players[i].vote_target;
            if (t >= 0 && t < GAME_MAX_PLAYERS) votes[t]++;
        }
    }

    // 최다 득표 슬롯과 동점 여부 판정
    int max_votes = -1, max_slot = -1, tie = 0;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (!gs->players[i].in_use) continue;
        if (votes[i] > max_votes) { max_votes = votes[i]; max_slot = i; tie = 0; }
        else if (votes[i] == max_votes) { tie = 1; }
    }

    // 동점이면 재투표 없이 라이어 승. 아니면 최다 득표가 라이어일 때만 시민 승.
    if (tie || max_slot != gs->liar_index) gs->result = RESULT_LIAR_WIN;
    else gs->result = RESULT_CITIZEN_WIN;

    gs->phase = PHASE_END;
    util_log_write(LOG_INFO, "game: 판정 결과=%s (최다슬롯=%d 동점=%d 라이어=%d)",
                   gs->result == RESULT_CITIZEN_WIN ? "시민승" : "라이어승",
                   max_slot, tie, gs->liar_index);
}

int game_submit_vote(game_state* gs, int voter, int target) {
    if (!valid_index(gs, voter) || !valid_index(gs, target)) return 0;
    if (gs->phase != PHASE_VOTE) return 0;
    if (gs->players[voter].voted) return 0;                  // 중복 투표 차단

    gs->players[voter].voted = 1;
    gs->players[voter].vote_target = target;
    util_log_write(LOG_INFO, "game: 슬롯 %d -> 슬롯 %d 투표", voter, target);

    // 전원 투표 완료 확인
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use && !gs->players[i].voted) return 1;
    }
    tally_and_judge(gs);
    return 1;
}

game_result game_judge(const game_state* gs) {
    if (gs == NULL || gs->phase != PHASE_END) return RESULT_NONE;
    return gs->result;
}
