#include "client.h"
#include "server.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define PASSWORD_MAX_BYTE 256
#define SERVER_DIR        "SERVER"
#define CLIENT_DIR        "CLIENT"

static void usage(const char* program) {
    fprintf(stderr,
            "사용법:\n"
            "  %s server <port> [words_dir] [players:3|4] [encrypted_key_file]\n"
            "  %s client <host> <port> [encrypted_key_file]\n"
            "개인키 암호는 LIAR_KEY_PASSWORD 환경 변수 또는 프롬프트로 입력합니다.\n",
            program, program);
}

static int parse_number(const char* text, int min, int max, int* out) {
    if (text == NULL || out == NULL) return 0;
    errno = 0;
    char* end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < min || value > max)
        return 0;
    *out = (int)value;
    return 1;
}

static int read_password(unsigned char out[PASSWORD_MAX_BYTE], size_t* out_len) {
    const char* environment = getenv("LIAR_KEY_PASSWORD");
    if (environment != NULL && environment[0] != '\0') {
        size_t len = strlen(environment);
        if (len >= PASSWORD_MAX_BYTE) return 0;
        memcpy(out, environment, len);
        *out_len = len;
        return 1;
    }

    struct termios old_settings;
    struct termios new_settings;
    int hide_input = isatty(STDIN_FILENO) &&
                     tcgetattr(STDIN_FILENO, &old_settings) == 0;
    if (hide_input) {
        new_settings = old_settings;
        new_settings.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_settings);
    }

    fprintf(stderr, "개인키 암호: ");
    fflush(stderr);
    char buffer[PASSWORD_MAX_BYTE];
    char* result = fgets(buffer, sizeof buffer, stdin);
    if (hide_input) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_settings);
        fputc('\n', stderr);
    }
    if (result == NULL) return 0;

    size_t len = strlen(buffer);
    while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r'))
        buffer[--len] = '\0';
    if (len == 0) {
        OPENSSL_cleanse(buffer, sizeof buffer);
        return 0;
    }
    memcpy(out, buffer, len);
    *out_len = len;
    OPENSSL_cleanse(buffer, sizeof buffer);
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "server") == 0) {
        int port;
        int players = GAME_MAX_PLAYERS;
        if (argc < 3 || argc > 6 ||
            parse_number(argv[2], 1, 65535, &port) != 1 ||
            (argc >= 5 && parse_number(argv[4], GAME_MIN_PLAYERS,
                                        GAME_MAX_PLAYERS, &players) != 1)) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        const char* words_dir = argc >= 4 ? argv[3] : "WORDS";
        const char* key_path = argc >= 6 ? argv[5] : SERVER_DIR "/server-key.enc";
        unsigned char password[PASSWORD_MAX_BYTE];
        size_t password_len = 0;
        if (util_ensure_dir(SERVER_DIR) != 1) {
            fprintf(stderr, "%s 디렉터리를 만들지 못했습니다.\n", SERVER_DIR);
            return EXIT_FAILURE;
        }
        if (read_password(password, &password_len) != 1) {
            fprintf(stderr, "비어 있지 않은 서버 개인키 암호가 필요합니다.\n");
            return EXIT_FAILURE;
        }
        if (util_log_init(SERVER_DIR "/server.log", LOG_DEBUG) != 1) {
            fprintf(stderr, "서버 로그 파일을 열지 못했습니다.\n");
            OPENSSL_cleanse(password, sizeof password);
            return EXIT_FAILURE;
        }
        int success = server_run(port, words_dir, players, key_path,
                                 password, password_len);
        OPENSSL_cleanse(password, sizeof password);
        util_log_close();
        return success ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (strcmp(argv[1], "client") == 0) {
        int port;
        if (argc < 4 || argc > 5 ||
            parse_number(argv[3], 1, 65535, &port) != 1) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        unsigned char password[PASSWORD_MAX_BYTE];
        size_t password_len = 0;
        if (util_ensure_dir(CLIENT_DIR) != 1) {
            fprintf(stderr, "%s 디렉터리를 만들지 못했습니다.\n", CLIENT_DIR);
            return EXIT_FAILURE;
        }
        if (read_password(password, &password_len) != 1) {
            fprintf(stderr, "비어 있지 않은 개인키 암호가 필요합니다.\n");
            return EXIT_FAILURE;
        }
        const char* key_path = argc == 5 ? argv[4] : CLIENT_DIR "/client-key.enc";
        int success = client_run(argv[2], port, key_path, password, password_len);
        OPENSSL_cleanse(password, sizeof password);
        return success ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    usage(argv[0]);
    return EXIT_FAILURE;
}
