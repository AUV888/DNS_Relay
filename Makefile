CC       = gcc

# ---- Build mode selection -----------------------------------------------
# Default: release with aggressive optimization.  The flag set below is
# the maximum common subset accepted without warnings by BOTH Apple
# Clang (macOS) and GCC (Linux).
#
# Run `make debug` to swap to -O0 -g -Wall and rebuild.
ifeq ($(DEBUG),1)
CFLAGS    = -O0 -g -Wall -fsanitize=thread
LDFLAGS   =
OBJDIR    = bin/debug
else
# Compile-time flags.  -flto is here because the compiler must emit LTO
# bytecode IR (not final machine code) so the linker can do whole-program
# optimization later.
CFLAGS    = -O3 -pipe -funroll-loops -ftree-vectorize -fomit-frame-pointer \
            -fno-stack-protector -fno-math-errno -fno-trapping-math \
            -funsafe-math-optimizations -ffast-math \
            -march=native -flto \
            -D_GNU_SOURCE \
			-pthread
# Link-time flags.  -flto triggers LTO at link time; -s strips the symbol
# table from the final binary (it is a linker flag, so it must NOT appear
# during -c compile steps — clang warns "-s is unused during compilation"
# and ld warns "-s is obsolete" if it's passed via the compiler driver
# incorrectly.  Keeping it here is clean on both toolchains).
LDFLAGS   = -flto -s
OBJDIR    = bin/obj
endif

# ---- Include path: every header under ./include is available ------------
INC_FLAGS = -I./include
HEADERS   = $(wildcard include/*.h)

# ---- DNS_Relay sources (every .c under ./src except DNS_logparser.c) -----
RELAY_SRC = $(filter-out src/DNS_logparser.c, $(wildcard src/*.c))
RELAY_OBJ = $(patsubst src/%.c, $(OBJDIR)/%.o, $(RELAY_SRC))

# ---- Output binaries ----------------------------------------------------
TARGET    = ./bin/DNS_Relay
PARSER    = ./bin/Parser

.PHONY: all build debug clean

all: build

# (1) Build ./bin/DNS_Relay from all .c under ./src (except DNS_logparser.c)
# (2) Build ./bin/Parser from ./src/DNS_logparser.c as a single TU
build: $(TARGET) $(PARSER)

# Compile a .c into a .o (release or debug, selected by CFLAGS).
# Every header under ./include is on the search path (-I./include), so
# each source file's own #include directives resolve normally.
$(OBJDIR)/%.o: src/%.c $(HEADERS)
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

# Link all relay objects into ./bin/DNS_Relay.
$(TARGET): $(RELAY_OBJ)
	@mkdir -p ./bin
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

# Parser is a standalone single-TU build.
$(PARSER): src/DNS_logparser.c $(HEADERS)
	@mkdir -p ./bin
	$(CC) $(CFLAGS) $(INC_FLAGS) $(LDFLAGS) -o $@ $<

# Debug build: recurse with DEBUG=1 so CFLAGS swaps to -O0 -g -Wall.
debug:
	$(MAKE) build DEBUG=1

# Remove every .o anywhere under ./bin, plus the two binaries.
clean:
	rm -f $(TARGET) $(PARSER)
	rm -rf bin/obj bin/debug
	rm -f bin/*.o
