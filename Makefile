CC      := gcc
CFLAGS  := -O2 -Wall -Wextra -fPIC
LDFLAGS := -shared
LIBS    := -lseccomp

TARGET  := nonet_sandbox.so
SRC     := nonet_sandbox.c

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	uv run pytest
