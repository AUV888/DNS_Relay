CC      = gcc
CFLAGS  = -Wall -g -O0 -I./include
SRC     = $(wildcard src/*.c)
OBJ     = $(SRC:.c=.o)
TARGET  = ./bin/DNS_Relay

$(TARGET): $(OBJ)
	@mkdir -p ./bin
	$(CC) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: clean