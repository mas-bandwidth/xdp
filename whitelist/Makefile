
KERNEL = $(shell uname -r)

.PHONY: build
build: whitelist.c whitelist_xdp.o
	gcc -O2 -g whitelist.c -o whitelist -lxdp /usr/src/linux-headers-$(KERNEL)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lz -lelf

whitelist_xdp.o: whitelist_xdp.c
	clang -O2 -g -Ilibbpf/src -target bpf -c whitelist_xdp.c -o whitelist_xdp.o

.PHONY: clean
clean:
	rm -f whitelist
	rm -f *.o