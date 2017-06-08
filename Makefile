obj-m := tcpsecrets.o

KVER  ?= $(shell uname -r)
KDIR  ?=  /lib/modules/${KVER}/build
PWD   := $(shell pwd)

default: system_map.inc
	$(MAKE) -C $(KDIR) M=$(PWD) modules

system_map.inc: /boot/System.map-${KVER}
	@awk '/syncookie_secret/ { printf("#define SYNCOOKIE_SECRET_ADDR 0x%s\n", $$1) }' $< > $@

clean: 
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.ko Module.symvers
	@rm -f .*.*.cmd *~ *.*~ TODO.* *.inc
	@rm -fR .tmp* 
	@rm -rf .tmp_versions 
disclean: clean 
	@rm *.ko *.symvers
