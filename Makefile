CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -fPIC
LDFLAGS := -shared
LIBS    := -lseccomp

TARGET  := nonet_sandbox.so
SRC     := nonet_sandbox.c
UV_CACHE_DIR       ?= $(CURDIR)/.uv-cache
BENCH_REPEATS     ?= 7
BENCH_PLAIN_CALLS ?= 200000
BENCH_NONET_CALLS ?= 200

.PHONY: all clean test bench benchmark shows

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv run pytest

bench benchmark: $(TARGET)
	NONET_QUIET=1 UV_CACHE_DIR=$(UV_CACHE_DIR) uv run python bench_nonet.py \
		--repeats $(BENCH_REPEATS) \
		--plain-calls $(BENCH_PLAIN_CALLS) \
		--nonet-calls $(BENCH_NONET_CALLS)

shows: benchmark
