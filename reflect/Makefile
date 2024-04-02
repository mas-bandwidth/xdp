
KERNEL = $(shell uname -r)

.PHONY: build
build: reflect.c reflect_xdp.o
	gcc -O2 -g reflect.c -o reflect -lxdp /usr/src/linux-headers-$(KERNEL)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lz -lelf

reflect_xdp.o: reflect_xdp.c
	clang -O2 -g -Ilibbpf/src -target bpf -c reflect_xdp.c -o reflect_xdp.o

.PHONY: clean
clean:
	rm -f reflect
	rm -f *.o