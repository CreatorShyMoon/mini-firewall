# Root Makefile for mini-firewall project
# Author: Albert Adamyan <albertadaman70@gmail.com>

.PHONY: all kernel cli clean load unload test status reload

all: kernel cli

kernel:
	@echo "==> Building mini-firewall Linux Kernel Module..."
	$(MAKE) -C kernel

cli:
	@echo "==> Building fwctl User Space CLI utility..."
	$(MAKE) -C cli

load:
	@echo "==> Inserting mini_firewall.ko into Linux Kernel..."
	@sudo insmod kernel/mini_firewall.ko
	@echo "==> Checking dmesg output:"
	@sudo dmesg | tail -n 5

unload:
	@echo "==> Removing mini_firewall from Linux Kernel..."
	@sudo rmmod mini_firewall || true
	@echo "==> Checking dmesg output:"
	@sudo dmesg | tail -n 5

reload: unload load

test:
	@echo "==> Running automated test suite..."
	@sudo ./tests/test_firewall.sh

status:
	@./cli/fwctl status

clean:
	@echo "==> Cleaning build artifacts..."
	$(MAKE) -C kernel clean
	$(MAKE) -C cli clean
