obj-m := tcpsecrets.o

KVER  ?= $(shell uname -r)
KDIR  ?=  /lib/modules/${KVER}/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean: 
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.ko Module.symvers
	@rm -f .*.*.cmd *~ *.*~ TODO.* *.inc
	@rm -fR .tmp* 
	@rm -rf .tmp_versions 
disclean: clean 
	@rm *.ko *.symvers
