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

PROFILE_CALLS     ?= 300
PROFILE_TOP       ?= 20
PROFILE_SORT      ?= cumtime
PROFILE_OUT       ?= profile.speedscope.json

.PHONY: all clean test bench benchmark shows profile flamegraph

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

profile: $(TARGET)
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv run python profile_nonet.py \
		--calls   $(PROFILE_CALLS) \
		--top     $(PROFILE_TOP)   \
		--sort    $(PROFILE_SORT)  \
		--flamegraph               \
		--out     $(PROFILE_OUT)

flamegraph: profile
	npx --yes speedscope $(PROFILE_OUT)
