CC      = gcc
CFLAGS  = -Wall -g -O0 -I./include
SRC     = $(wildcard src/*.c)
OBJ     = $(patsubst src/%.c, bin/%.o, $(SRC))
TARGET  = ./bin/DNS_Relay

$(TARGET): $(OBJ)
	@mkdir -p ./bin
	$(CC) $^ -o $@

bin/%.o: src/%.c
	@mkdir -p ./bin
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

run: $(TARGET)
	$(TARGET)

.PHONY: clean