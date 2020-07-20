CC	= clang
CFLAGS	= -std=gnu99 -ggdb
UNAME_M := $(shell uname -m)

.PHONY: x86_64

all:injectme.so
ifeq ($(UNAME_M),x86_64)
	$(MAKE) x86_64
endif
ifeq ($(UNAME_M),x86)
	$(MAKE) x64
endif
ifneq (,$(findstring arm,$(UNAME_M)))
	$(MAKE) arm
endif

x86_64:
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c inject-x86_64.c -ldl
	$(CC) -m32 $(CFLAGS) -o inject32 utils.c ptrace.c inject-x86.c -ldl

injectme.so:injectme.c
	gcc injectme.c -o injectme.so --shared -fPIC

clean:
	rm -f inject
	rm -f inject32
	rm -f injectme.so
