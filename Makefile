obj-m += cve_2026_31431_live_mitigation.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	rmmod algif_aead 2>&1 | grep builtin > /dev/null
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	cp cve_2026_31431_live_mitigation.conf /etc/modules-load.d/
