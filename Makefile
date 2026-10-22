CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wpedantic -std=c11 \
           -D_GNU_SOURCE \
           -O3 -g

SRC_DIR    := src
SRC     := $(SRC_DIR)/proxy.c
SRC_V2  := $(SRC_DIR)/proxy-v2.c
TARGET  := proxy proxy-v2

.PHONY: all proxy proxy-v2 clean

all: $(TARGET)

proxy: $(SRC)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< -lssl -lcrypto

proxy-v2: $(SRC_V2)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< -lssl -lcrypto

clean:
	rm -f $(TARGET)
