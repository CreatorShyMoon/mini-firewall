CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -std=c99

TARGET = fwctl
SRC = fwctl.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)
