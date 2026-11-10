// 프로젝트에서 유틸리티(로그 파일 로드, 기록, 해제) 관련 기능만 모아놓은 헤더 파일
#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>   // 가변 인자 처리를 사용하는 선언을 위해


// 로그 레벨 분리 -> 어떤 종류의 로그인지 구분하기 위해
// 값이 작을수록 더 상세한(덜 중요한) 로그, 클수록 더 심각한 로그
typedef enum {
    LOG_DEBUG,   // 개발/디버깅용 상세 정보
    LOG_INFO,    // 정상 동작 중 남기는 일반 정보
    LOG_WARN,    // 문제는 아니지만 주의가 필요한 상황
    LOG_ERROR    // 실패/오류 상황
} log_level;


// 함수 선언부
// 공통 규약: 성공 시 1, 실패 시 0 반환

// 로그 시스템 초기화
// path: 로그를 기록할 대상 파일
int util_log_init(const char* path, log_level level);

// 로그 한 줄 기록 (fmt_msg: 포맷 문자열 & ... : 값을 끼워 넣을 수 있는 포맷 기능)
// level이 init에서 지정한 최소 레벨보다 낮으면 기록하지 않고 성공 처리한다.
int util_log_write(log_level level, const char* fmt_msg, ...);

// 로그 시스템 해제 (열어 둔 파일을 닫고 내부 상태 정리, 받는 인자 없음)
int util_log_close(void);


#endif