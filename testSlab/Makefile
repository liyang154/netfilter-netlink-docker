obj-m := testSlab.o


PWD := $(shell pwd)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build

modules:
	@$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	@rm -rf *.ko *.o *.mod.c *symvers *order .nl* .tmp* *.cmd
install:
	/sbin/insmod testSlab.ko
remove:
	/sbin/rmmod testSlab

	
