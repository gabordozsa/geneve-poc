CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wpedantic -std=c11 \
           -D_GNU_SOURCE \
           -O3 -g

SRC_DIR    := src
SRC     := $(SRC_DIR)/proxy.c
TARGET  := proxy

.PHONY: all proxy clean

all: $(TARGET)

proxy: $(SRC)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< -lssl -lcrypto

clean:
	rm -f $(TARGET)
