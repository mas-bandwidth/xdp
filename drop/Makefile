
KERNEL = $(shell uname -r)

.PHONY: build
build: drop.c drop_xdp.o
	gcc -O2 -g drop.c -o drop -lxdp /usr/src/linux-headers-$(KERNEL)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lz -lelf

drop_xdp.o: drop_xdp.c
	clang -O2 -g -Ilibbpf/src -target bpf -c drop_xdp.c -o drop_xdp.o

.PHONY: clean
clean:
	rm -f drop
	rm -f *.o