# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/selinux-policy/Library/common
#   Description: Wrapper library for /CoreOS/selinux-policy/common
#   Author: David Spurek <dspurek@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export TEST=/CoreOS/selinux-policy/Library/common
export TESTVERSION=1.0

BUILT_FILES=

FILES=$(METADATA) lib.sh Makefile runtest.sh mkcache.py

.PHONY: all install download clean

run: $(FILES)
	./runtest.sh

include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "Owner:           David Spurek <dspurek@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     Common library for SELinux" >> $(METADATA)
	@echo "Type:            Library" >> $(METADATA)
	@echo "TestTime:        120m" >> $(METADATA)
	@echo "Requires:        setools" >> $(METADATA)
	@echo "Requires:        setools-console" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Requires:        policycoreutils" >> $(METADATA)
	@echo "Requires:        /usr/sbin/semanage" >> $(METADATA)
	@echo "Requires:        selinux-policy-devel" >> $(METADATA)
	@echo "Requires:        yum-utils" >> $(METADATA)
	@echo "Requires:        python3 sqlite" >> $(METADATA)
	@echo "Provides:        library(selinux-policy/common)" >> $(METADATA)
	@echo "RhtsRequires:    library(distribution/epel)" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)
	@echo "Environment:     AVC_ERROR=+no_avc_check" >> $(METADATA)

	rhts-lint $(METADATA)

