obj-m +=netfilter_server.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
install:
	/sbin/insmod netfilter_server.ko
remove:
	/sbin/rmmod netfilter_server
