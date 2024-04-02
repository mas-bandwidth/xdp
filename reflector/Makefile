
KERNEL = $(shell uname -r)

.PHONY: build
build: reflector.c reflector_xdp.o
	gcc -O2 -g reflector.c -o reflector -lxdp /usr/src/linux-headers-$(KERNEL)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lz -lelf

reflector_xdp.o: reflector_xdp.c
	clang -O2 -g -Ilibbpf/src -target bpf -c reflector_xdp.c -o reflector_xdp.o

.PHONY: clean
clean:
	rm -f reflector
	rm -f *.o