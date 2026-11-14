CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
LDLIBS = -lcrypto -pthread

GAME_OBJECTS = main.o client.o server.o game.o protocol.o crypto.o util.o
SECURITY_OBJECTS = security_demo.o game.o protocol.o crypto.o util.o

.PHONY: all test clean

all: liar_game security_demo

liar_game: $(GAME_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(GAME_OBJECTS) $(LDLIBS)

security_demo: $(SECURITY_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(SECURITY_OBJECTS) $(LDLIBS)

test: all
	./security_demo

clean:
	rm -f *.o liar_game security_demo hybrid_demo

hybrid_demo: hybrid_rsa_aes_pss.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto
