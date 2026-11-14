// 프로젝트에서 게임 진행 기능만 모아놓은 헤더 파일
#ifndef GAME_H
#define GAME_H

#include "crypto.h"
#include "util.h"
#include <stddef.h>

// 게임 규모
#define GAME_MAX_PLAYERS    4
#define GAME_MIN_PLAYERS    3
#define HINT_ROUNDS         2       // 발언 바퀴 수 (1인당 총 발언 수)
#define WORD_MAX_BYTE       64      // 제시어/카테고리 최대 바이트
#define CATEGORY_MAX_BYTE   64

// 게임 페이즈 상태기계
typedef enum {
    PHASE_LOBBY,    // 준비 대기
    PHASE_ASSIGN,   // 제시어 전달 및 커밋
    PHASE_HINT,     // 발언 (2바퀴)
    PHASE_VOTE,     // 투표
    PHASE_END       // 승패 결정, 커밋 공개
} game_phase;

// 승패 결과
typedef enum {
    RESULT_NONE = 0,
    RESULT_CITIZEN_WIN,  // 시민 승 (라이어 정확히 지목)
    RESULT_LIAR_WIN      // 라이어 승 (오지목 또는 동점)
} game_result;

// 플레이어 1명의 상태
typedef struct {
    unsigned char id[GAME_ID_BYTE];   // sender_id
    int in_use;                       // 슬롯 사용 중 여부
    int ready;                        // READY 수신 여부
    int hints_used;                   // 지금까지 한 발언 수 (0..HINT_ROUNDS)
    int vote_target;                  // 투표한 상대 슬롯 번호 (-1 = 미투표)
    int voted;                        // 투표 완료 여부
} player_slot;

// 전역 게임 상태 (server.c가 전역 1개 + Mutex 1개로 보호)
typedef struct {
    game_phase phase;
    int player_count;                 // 현재 접속 인원
    player_slot players[GAME_MAX_PLAYERS];

    int liar_index;                   // 라이어 슬롯 번호
    char category[CATEGORY_MAX_BYTE]; // 카테고리명
    char word[WORD_MAX_BYTE];         // 제시어

    // 공정성 커밋: hash(liar_id || nonce)
    unsigned char commit_nonce[COMMIT_NONCE_BYTE];
    unsigned char commit_hash_val[SHA256_BYTE];

    int turn_order[GAME_MAX_PLAYERS]; // 발언 순서 (접속 순서)
    int turn_cursor;                  // turn_order상 현재 발언자 위치
    int hint_total;                   // 전체 누적 발언 수

    game_result result;               // 판정 결과
} game_state;


// ===== 함수 선언 (공통 규약: 성공 1, 실패 0. 호출자가 락을 쥔다고 가정) =====

// 게임 상태 초기화 (LOBBY, 인원 0).
void game_init(game_state* gs);

// 플레이어 슬롯 추가. 성공 시 슬롯 번호(0~)를 *out_index로 반환.
// 정원 초과 또는 LOBBY가 아니면 실패.
int game_add_player(game_state* gs, const unsigned char id[GAME_ID_BYTE], int* out_index);

// 플레이어를 READY로 표시. 유효하지 않은 슬롯이면 실패.
int game_set_ready(game_state* gs, int index);

// 모두 준비됐는지 (최소 인원 이상 && 전원 ready).
int game_all_ready(const game_state* gs);

// 카테고리 디렉터리에서 랜덤 카테고리/제시어를 골라 배정하고,
// 라이어를 랜덤 지정한 뒤 커밋 해시를 계산한다. 상태를 ASSIGN으로 전이.
// dir_path: WORDS 폴더 경로.
int game_assign(game_state* gs, const char* dir_path);

// 특정 슬롯에게 보낼 제시어 문자열을 구성한다 (개인 세션키 전송용).
// 시민: "category|word", 라이어: "category|" (제시어 미포함).
// 성공 시 buf에 널 종단 문자열을 채운다.
int game_word_for(const game_state* gs, int index, char* buf, size_t buf_len);

// 커밋을 ASSIGN에서 HINT로 넘기며 발언 페이즈 시작.
int game_start_hints(game_state* gs);

// 현재 발언자 슬롯 번호를 반환 (-1이면 발언 페이즈 종료).
int game_current_speaker(const game_state* gs);

// 현재 발언자가 발언을 마쳤음을 기록하고 턴을 다음으로 넘긴다.
// index가 현재 발언자가 아니거나 발언 횟수를 초과하면 실패.
// 모든 발언이 끝나면 자동으로 VOTE 페이즈로 전이.
int game_submit_hint(game_state* gs, int index);

// 투표 기록. voter가 target 슬롯을 지목. 서명 검증은 호출자(server)가 선행.
// 중복 투표/잘못된 슬롯이면 실패. 전원 투표 완료 시 END로 전이하며 판정.
int game_submit_vote(game_state* gs, int voter, int target);

// 판정 결과 반환 (END 페이즈에서 유효).
game_result game_judge(const game_state* gs);

#endif
