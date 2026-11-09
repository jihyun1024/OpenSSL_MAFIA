// 프로젝트에서 유틸리티 관련 기능만 모아놓은 헤더 파일
// 로그, 제시어 목록 로딩
#ifndef UTIL_H
#define UTIL_H


// 함수 선언부
int util_log_init();
int util_log();
int util_log_close();
int load_wordlist();


#endif