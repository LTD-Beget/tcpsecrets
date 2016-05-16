obj-m := tcpsecrets.o 

KDIR  :=  /lib/modules/`uname -r`/build
PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean: 
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.ko Module.symvers
	@rm -f .*.*.cmd *~ *.*~ TODO.* 
	@rm -fR .tmp* 
	@rm -rf .tmp_versions 
disclean: clean 
	@rm *.ko *.symvers
