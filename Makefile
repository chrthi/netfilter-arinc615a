# SPDX-License-Identifier: GPL-2.0-only
#
# Out-of-tree build of the ARINC 615A conntrack/NAT helpers.
#
#   make                      build against the running kernel
#   make KDIR=/path/to/linux  build against another kernel tree
#   make modules_install      install into /lib/modules/<version>/updates

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: modules

modules modules_install clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $@

.PHONY: all modules modules_install clean
