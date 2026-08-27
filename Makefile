CC      ?= gcc
CFLAGS  := -Wall -Wextra -Wpedantic -std=c11 \
           -D_GNU_SOURCE \
           -O2 -g

SRC_DIR := src
SRCS    := $(SRC_DIR)/main.c $(SRC_DIR)/geneve.c
OBJS    := $(SRCS:.c=.o)
TARGET  := geneve

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/geneve.h
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)
