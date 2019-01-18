KDIR = /lib/modules/`uname -r`/build
MODULE_NAME = griffin

kbuild:
	make -C $(KDIR) M=`pwd`

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

rebuild: clean kbuild

fmt:
	find . -name "*.c" -o -name "*.h" | \
		xargs clang-format -style=file -i

install: kbuild
	-exec sudo -- rmmod $(MODULE_NAME) # Will continue even after a failure #
	exec sudo -- insmod $(addsuffix .ko,$(MODULE_NAME))