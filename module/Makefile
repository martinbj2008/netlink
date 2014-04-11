#Makefile for hello.c file

obj-m += martin_netlink.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@rm -fr martin_netlink.ko  martin_netlink.mod.c  martin_netlink.mod.o  martin_netlink.o

