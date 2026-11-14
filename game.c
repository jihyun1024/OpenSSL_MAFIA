#include "game.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

// [0, n) 범위의 편향 없는 난수를 만든다.
static int rand_below(int n, int* out) {
    if (n <= 0 || out == NULL) return 0;

    unsigned int value;
    unsigned int limit = UINT_MAX - (UINT_MAX % (unsigned int)n);
    do {
        if (rand_bytes((unsigned char*)&value, sizeof value) != 1) return 0;
    } while (value >= limit);

    *out = (int)(value % (unsigned int)n);
    return 1;
}

static int valid_index(const game_state* gs, int index) {
    return gs != NULL && index >= 0 && index < GAME_MAX_PLAYERS &&
           gs->players[index].in_use;
}

void game_init(game_state* gs) {
    if (gs == NULL) return;
    memset(gs, 0, sizeof *gs);
    gs->phase = PHASE_LOBBY;
    gs->liar_index = -1;
    gs->result = RESULT_NONE;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++)
        gs->players[i].vote_target = -1;
}

int game_add_player(game_state* gs, const unsigned char id[GAME_ID_BYTE], int* out_index) {
    if (gs == NULL || id == NULL || out_index == NULL ||
        gs->phase != PHASE_LOBBY || gs->player_count >= GAME_MAX_PLAYERS)
        return 0;

    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use &&
            CRYPTO_memcmp(gs->players[i].id, id, GAME_ID_BYTE) == 0)
            return 0;
    }

    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (!gs->players[i].in_use) {
            player_slot* player = &gs->players[i];
            memset(player, 0, sizeof *player);
            memcpy(player->id, id, GAME_ID_BYTE);
            player->in_use = 1;
            player->vote_target = -1;
            gs->turn_order[gs->player_count++] = i;
            *out_index = i;
            util_log_write(LOG_INFO, "game: 플레이어 슬롯 %d 추가 (현재 %d명)",
                           i, gs->player_count);
            return 1;
        }
    }
    return 0;
}

int game_remove_player(game_state* gs, int index) {
    if (!valid_index(gs, index) || gs->phase != PHASE_LOBBY) return 0;

    int order_index = -1;
    for (int i = 0; i < gs->player_count; i++) {
        if (gs->turn_order[i] == index) {
            order_index = i;
            break;
        }
    }
    if (order_index < 0) return 0;

    for (int i = order_index; i + 1 < gs->player_count; i++)
        gs->turn_order[i] = gs->turn_order[i + 1];
    gs->turn_order[gs->player_count - 1] = 0;
    memset(&gs->players[index], 0, sizeof gs->players[index]);
    gs->players[index].vote_target = -1;
    gs->player_count--;
    util_log_write(LOG_INFO, "game: 로비에서 슬롯 %d 제거 (현재 %d명)",
                   index, gs->player_count);
    return 1;
}

int game_set_ready(game_state* gs, int index) {
    if (!valid_index(gs, index) || gs->phase != PHASE_LOBBY) return 0;
    gs->players[index].ready = 1;
    util_log_write(LOG_INFO, "game: 슬롯 %d READY", index);
    return 1;
}

int game_all_ready(const game_state* gs) {
    if (gs == NULL || gs->phase != PHASE_LOBBY ||
        gs->player_count < GAME_MIN_PLAYERS)
        return 0;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use && !gs->players[i].ready) return 0;
    }
    return 1;
}

static int pick_category_file(const char* dir_path, char* name_out, size_t name_len) {
    if (dir_path == NULL || name_out == NULL || name_len == 0) return 0;
    DIR* dir = opendir(dir_path);
    if (dir == NULL) return 0;

    char names[64][CATEGORY_MAX_BYTE];
    int count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && count < 64) {
        size_t entry_len = strlen(entry->d_name);
        const char* dot = strrchr(entry->d_name, '.');
        if (dot != NULL && strcmp(dot, ".txt") == 0 &&
            entry_len < sizeof names[count]) {
            memcpy(names[count], entry->d_name, entry_len + 1);
            count++;
        }
    }
    closedir(dir);
    if (count == 0) return 0;

    int pick;
    if (rand_below(count, &pick) != 1) return 0;
    int written = snprintf(name_out, name_len, "%s", names[pick]);
    return written >= 0 && (size_t)written < name_len;
}

static int pick_word_from_file(const char* path, char* word_out, size_t word_len) {
    if (path == NULL || word_out == NULL || word_len == 0) return 0;
    FILE* fp = fopen(path, "r");
    if (fp == NULL) return 0;

    char line[WORD_MAX_BYTE];
    char chosen[WORD_MAX_BYTE] = {0};
    int count = 0;
    int success = 0;
    while (fgets(line, sizeof line, fp) != NULL) {
        size_t len = strlen(line);
        if (len == sizeof line - 1 && line[len - 1] != '\n' && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            continue;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0) continue;

        count++;
        int pick;
        if (rand_below(count, &pick) != 1) goto done;
        if (pick == 0) memcpy(chosen, line, len + 1);
    }
    if (count == 0) goto done;

    int written = snprintf(word_out, word_len, "%s", chosen);
    success = written >= 0 && (size_t)written < word_len;

done:
    fclose(fp);
    return success;
}

int game_assign(game_state* gs, const char* dir_path) {
    if (gs == NULL || dir_path == NULL || gs->phase != PHASE_LOBBY ||
        !game_all_ready(gs))
        return 0;

    char file_name[CATEGORY_MAX_BYTE];
    if (pick_category_file(dir_path, file_name, sizeof file_name) != 1) return 0;

    int written = snprintf(gs->category, sizeof gs->category, "%s", file_name);
    if (written < 0 || (size_t)written >= sizeof gs->category) return 0;
    char* dot = strrchr(gs->category, '.');
    if (dot != NULL) *dot = '\0';

    char path[512];
    written = snprintf(path, sizeof path, "%s/%s", dir_path, file_name);
    if (written < 0 || (size_t)written >= sizeof path ||
        pick_word_from_file(path, gs->word, sizeof gs->word) != 1)
        return 0;

    int order_pick;
    if (rand_below(gs->player_count, &order_pick) != 1) return 0;
    gs->liar_index = gs->turn_order[order_pick];

    if (rand_bytes(gs->commit_nonce, COMMIT_NONCE_BYTE) != 1 ||
        commit_hash((unsigned char)gs->liar_index, gs->commit_nonce,
                    gs->commit_hash_val) != 1)
        return 0;

    gs->phase = PHASE_ASSIGN;
    util_log_write(LOG_INFO, "game: ASSIGN 카테고리=%s 라이어슬롯=%d",
                   gs->category, gs->liar_index);
    return 1;
}

int game_word_for(const game_state* gs, int index, char* buf, size_t buf_len) {
    if (!valid_index(gs, index) || buf == NULL || buf_len == 0 ||
        (gs->phase != PHASE_ASSIGN && gs->phase != PHASE_HINT))
        return 0;

    int written;
    if (index == gs->liar_index)
        written = snprintf(buf, buf_len, "%s|", gs->category);
    else
        written = snprintf(buf, buf_len, "%s|%s", gs->category, gs->word);
    return written >= 0 && (size_t)written < buf_len;
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
    if (gs == NULL || gs->phase != PHASE_HINT || gs->player_count <= 0) return -1;
    int total_turns = gs->player_count * HINT_ROUNDS;
    if (gs->hint_total >= total_turns) return -1;
    return gs->turn_order[gs->turn_cursor % gs->player_count];
}

static void advance_hint(game_state* gs, int index, int timed_out) {
    gs->players[index].hints_used++;
    gs->hint_total++;
    gs->turn_cursor++;
    util_log_write(timed_out ? LOG_WARN : LOG_INFO,
                   timed_out ? "game: 슬롯 %d 발언 시간 초과 (%d/%d)" :
                               "game: 슬롯 %d 발언 (%d/%d)",
                   index, gs->players[index].hints_used, HINT_ROUNDS);

    if (gs->hint_total >= gs->player_count * HINT_ROUNDS) {
        gs->phase = PHASE_VOTE;
        util_log_write(LOG_INFO, "game: 발언 종료, VOTE 페이즈 전이");
    }
}

int game_submit_hint(game_state* gs, int index) {
    if (gs == NULL || gs->phase != PHASE_HINT) return 0;
    int speaker = game_current_speaker(gs);
    if (speaker < 0 || speaker != index ||
        gs->players[index].hints_used >= HINT_ROUNDS)
        return 0;

    advance_hint(gs, index, 0);
    return 1;
}

int game_timeout_hint(game_state* gs) {
    int speaker = game_current_speaker(gs);
    if (speaker < 0) return 0;
    advance_hint(gs, speaker, 1);
    return 1;
}

static void tally_and_judge(game_state* gs) {
    int votes[GAME_MAX_PLAYERS] = {0};
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (gs->players[i].in_use && gs->players[i].voted) {
            int target = gs->players[i].vote_target;
            if (valid_index(gs, target)) votes[target]++;
        }
    }

    int max_votes = -1;
    int max_slot = -1;
    int tie = 0;
    for (int i = 0; i < GAME_MAX_PLAYERS; i++) {
        if (!gs->players[i].in_use) continue;
        if (votes[i] > max_votes) {
            max_votes = votes[i];
            max_slot = i;
            tie = 0;
        } else if (votes[i] == max_votes) {
            tie = 1;
        }
    }

    gs->result = (!tie && max_slot == gs->liar_index) ?
                 RESULT_CITIZEN_WIN : RESULT_LIAR_WIN;
    gs->phase = PHASE_END;
    util_log_write(LOG_INFO, "game: 판정 결과=%s (최다슬롯=%d 동점=%d 라이어=%d)",
                   gs->result == RESULT_CITIZEN_WIN ? "시민승" : "라이어승",
                   max_slot, tie, gs->liar_index);
}

int game_submit_vote(game_state* gs, int voter, int target) {
    if (!valid_index(gs, voter) || !valid_index(gs, target) ||
        gs->phase != PHASE_VOTE || gs->players[voter].voted)
        return 0;

    gs->players[voter].voted = 1;
    gs->players[voter].vote_target = target;
    util_log_write(LOG_INFO, "game: 슬롯 %d -> 슬롯 %d 투표", voter, target);

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
