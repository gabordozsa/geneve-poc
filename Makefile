CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wpedantic -std=c11 \
           -D_GNU_SOURCE \
           -O2 -g

SRC_DIR := src
SRCS    := $(SRC_DIR)/main.c $(SRC_DIR)/geneve.c
OBJS    := $(SRCS:.c=.o)
TARGET     := geneve
PP_SRC     := $(SRC_DIR)/proxy.c
PP_TARGET  := proxy

.PHONY: all proxy clean

all: $(TARGET)

proxy: $(PP_SRC)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -o $@ $< -lssl -lcrypto

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/geneve.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET) $(PP_TARGET)
