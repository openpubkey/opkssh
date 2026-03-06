# Copyright 2025 OpenPubkey
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

DAEMON      := opkssh-nssd
SO          := libnss_opkssh.so.2
CC          ?= gcc
CFLAGS      ?= -O2 -Wall -Wextra -fstack-protector-strong
GO          ?= go

# Detect lib dir (Debian/Ubuntu multiarch, RHEL/Fedora, generic fallback)
LIBDIR      ?= $(shell \
  if gcc -print-multiarch 2>/dev/null | grep -q .; then \
    echo /usr/lib/$$(gcc -print-multiarch); \
  elif [ -d /usr/lib64 ]; then \
    echo /usr/lib64; \
  else \
    echo /usr/lib; \
  fi)
SBINDIR     ?= /usr/sbin
UNITDIR     ?= /etc/systemd/system

.PHONY: all daemon so install uninstall clean

all: $(SO) $(DAEMON)

$(SO): nss_opkssh.c
	$(CC) $(CFLAGS) -shared -fPIC -Wl,-soname,$(SO) \
	    -o $@ $< -lpthread
	@echo "Built $@"

$(DAEMON):
	cd daemon && $(GO) build -o ../$(DAEMON) .
	@echo "Built $(DAEMON)"

install: all
	install -Dm755 $(SO)     $(DESTDIR)$(LIBDIR)/$(SO)
	ldconfig
	install -Dm755 $(DAEMON) $(DESTDIR)$(SBINDIR)/$(DAEMON)
	install -Dm644 opkssh-nss.service $(DESTDIR)$(UNITDIR)/opkssh-nss.service
	@echo ""
	@echo "Next steps:"
	@echo "  1. Add 'opkssh' to the passwd AND shadow lines in /etc/nsswitch.conf:"
	@echo "       passwd: files opkssh"
	@echo "       shadow: files opkssh"
	@echo "     The shadow entry lets pam_unix.so find synthetic shadow records for"
	@echo "     JIT users so it returns PAM_SUCCESS instead of PAM_IGNORE, allowing"
	@echo "     the standard common-account PAM stack to work without modification."
	@echo "  2. Enable and start the daemon:"
	@echo "       systemctl daemon-reload"
	@echo "       systemctl enable --now opkssh-nss"

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(SO)
	rm -f $(DESTDIR)$(SBINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(UNITDIR)/opkssh-nss.service
	ldconfig

clean:
	rm -f $(SO) $(DAEMON)
