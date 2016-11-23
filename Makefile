target = catch
obj-m := $(target).o
#moudule_objs := sockfilter.o modu.o 
KERNELDIR = /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules

install:
	insmod $(target).ko

uninstall:
	rmmod $(target).ko

clean:
	rm -rf *.o *.mod.c *.ko
	rm -rf *.symvers .*cmd .tmp_versions *.order
