# Cross-language libsodium bench. macOS + Linux build.
#
#   brew install libsodium   # macOS
#   apt install libsodium-dev # Debian/Ubuntu
#
# Then:
#   make
#   ./bench

CC      ?= cc
CFLAGS  ?= -O3 -Wall -Wextra
LDLIBS  ?= -lsodium

# On macOS Homebrew installs sodium under /opt/homebrew (arm64) or
# /usr/local (Intel); add both candidate include paths.
ifeq ($(shell uname),Darwin)
  CFLAGS  += -I/opt/homebrew/include -I/usr/local/include
  LDFLAGS += -L/opt/homebrew/lib -L/usr/local/lib
endif

bench: main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ main.c $(LDLIBS)

run: bench
	./bench

clean:
	rm -f bench

.PHONY: run clean
