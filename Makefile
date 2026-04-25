CC ?= cc
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

TARGET := passmake

CFLAGS ?= -std=c11 -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
CFLAGS += -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
LDFLAGS ?= -Wl,-z,relro -Wl,-z,now -pie
LDLIBS ?=

.PHONY: all check install uninstall clean

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

check: all
	./$(TARGET) --version >/dev/null
	./$(TARGET) --help >/dev/null
	./$(TARGET) --security >/dev/null
	test "$$(./$(TARGET) --no-newline | wc -c | tr -d ' ')" = "24"
	test "$$(./$(TARGET) 32 --no-newline | wc -c | tr -d ' ')" = "32"

install: all
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(TARGET)" "$(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"

clean:
	rm -f "$(TARGET)"
