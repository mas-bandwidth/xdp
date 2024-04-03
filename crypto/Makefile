
KERNEL = $(shell uname -r)

.PHONY: build
build: crypto.c crypto_xdp.o
	gcc -O2 -g crypto.c -o crypto -lxdp /usr/src/linux-headers-$(KERNEL)/tools/bpf/resolve_btfids/libbpf/libbpf.a -lz -lelf

crypto_xdp.o: crypto_xdp.c
	clang -O2 -g -Ilibbpf/src -target bpf -c crypto_xdp.c -o crypto_xdp.o

.PHONY: clean
clean:
	rm -f crypto
	rm -f *.o

obj-m += crypto_module.o

module: crypto_module.c
	@echo building crypto module
	make -C /lib/modules/$(KERNEL)/build M=$(shell pwd) modules
	sudo insmod crypto_module.ko
