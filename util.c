#include "util.h"

#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <time.h>
#include <string.h>


// ===== 로그 모듈 내부 상태 =====
// init에서 설정하고 write에서 사용하며 close에서 정리하는 공유 상태.
//  - g_log_fp     : 로그를 기록할 대상 (파일 또는 stderr)
//  - g_log_level  : init에서 지정한 최소 출력 레벨
//  - g_log_lock   : 여러 스레드가 동시에 기록할 때 줄이 섞이지 않도록 보호
//  - g_log_is_file: g_log_fp가 우리가 직접 연 파일인지(close에서 fclose 대상인지) 구분
static FILE* g_log_fp = NULL;
static log_level g_log_level = LOG_DEBUG;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_log_is_file = 0;


// 로그 시스템 초기화
// path가 NULL이면 파일 대신 stderr로 기록한다.
// level은 이 값 미만의 로그를 버리는 '최소 출력 레벨'로 사용한다.
// 성공 시 1, 실패 시 0 반환.
int util_log_init(const char* path, log_level level) {
    if (level < LOG_DEBUG || level > LOG_ERROR) return 0;

    pthread_mutex_lock(&g_log_lock);

    // 이미 초기화돼 있던 파일이 있으면 먼저 정리 (중복 init 대비)
    if (g_log_fp != NULL && g_log_is_file) {
        fclose(g_log_fp);
    }
    g_log_fp = NULL;
    g_log_is_file = 0;

    if (path == NULL) {
        // 파일 경로가 없으면 stderr로 기록 (stderr는 우리가 닫으면 안 됨)
        g_log_fp = stderr;
        g_log_is_file = 0;
    } else {
        // append 모드로 열어 기존 로그를 보존하며 이어 쓴다.
        FILE* fp = fopen(path, "a");
        if (fp == NULL) {
            pthread_mutex_unlock(&g_log_lock);
            return 0;
        }
        g_log_fp = fp;
        g_log_is_file = 1;
    }

    g_log_level = level;

    pthread_mutex_unlock(&g_log_lock);
    return 1;
}


// 로그 한 줄 기록: "[타임스탬프] [레벨] 내용물\n" 형식으로 기록한다.
// level이 init에서 지정한 최소 레벨보다 낮으면 기록하지 않고 성공 처리한다.
// 성공 시 1, 실패 시 0 반환.
int util_log_write(log_level level, const char* fmt_msg, ...) {
    // 레벨 문자열 변환용 테이블 (enum 값 순서와 일치해야 함)
    static const char* const LEVEL_STR[] = { "DEBUG", "INFO", "WARN", "ERROR" };

    if (fmt_msg == NULL) return 0;
    if (level < LOG_DEBUG || level > LOG_ERROR) return 0;

    // 1) 타임스탬프 문자열 생성 ("YYYY-MM-DD HH:MM:SS")
    char timestamp[20];
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);   // 스레드 안전 버전
    strftime(timestamp, sizeof timestamp, "%Y-%m-%d %H:%M:%S", &tm_buf);

    int success = 0;

    // 2) 한 줄이 통째로 기록되도록 락으로 보호
    pthread_mutex_lock(&g_log_lock);

    // 초기화되지 않았으면 실패 (락 안에서 확인해야 close와 경쟁하지 않음)
    if (g_log_fp == NULL) {
        pthread_mutex_unlock(&g_log_lock);
        return 0;
    }

    // 최소 레벨보다 낮은 로그는 기록하지 않되, 실패는 아니므로 성공으로 처리
    if (level < g_log_level) {
        pthread_mutex_unlock(&g_log_lock);
        return 1;
    }

    // 접두어: "[타임스탬프] [레벨] "
    if (fprintf(g_log_fp, "[%s] [%s] ", timestamp, LEVEL_STR[level]) < 0)
        goto done;

    // 내용물: fmt_msg + 가변 인자를 printf 형식으로 전개
    va_list args;
    va_start(args, fmt_msg);
    int written = vfprintf(g_log_fp, fmt_msg, args);
    va_end(args);
    if (written < 0) goto done;

    // 줄 끝 개행 -> 로그 한 건이 정확히 한 줄이 되도록
    if (fputc('\n', g_log_fp) == EOF) goto done;

    // 크래시 시 유실을 막기 위해 즉시 flush
    if (fflush(g_log_fp) != 0) goto done;

    success = 1;

done:
    pthread_mutex_unlock(&g_log_lock);
    return success;
}


// 로그 시스템 해제: 우리가 연 파일이면 닫고 내부 상태를 정리한다.
// stderr는 우리가 연 게 아니므로 닫지 않는다.
// 성공 시 1, 실패 시 0 반환.
int util_log_close(void) {
    int result = 1;

    pthread_mutex_lock(&g_log_lock);

    if (g_log_fp != NULL && g_log_is_file) {
        if (fclose(g_log_fp) != 0) result = 0;
    }
    g_log_fp = NULL;
    g_log_is_file = 0;

    pthread_mutex_unlock(&g_log_lock);
    return result;
}
