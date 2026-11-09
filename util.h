// 프로젝트에서 유틸리티(로그 파일 로드, 기록, 해제) 관련 기능만 모아놓은 헤더 파일
#ifndef UTIL_H
#define UTIL_H


// 함수 선언부
int util_log_init();
int util_log_write();
int util_log_close();


#endif