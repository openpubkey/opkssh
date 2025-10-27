# Makefile for NSS opkssh module
#
# This builds the NSS module that allows JIT user provisioning to work

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2
LDFLAGS = -shared -Wl,-soname,libnss_opkssh.so.2

# Target library name
TARGET = libnss_opkssh.so.2
SONAME_LINK = libnss_opkssh.so

# Source files
SRCS = nss_opkssh.c
OBJS = $(SRCS:.c=.o)

# Installation directories
INSTALL_DIR = /lib/x86_64-linux-gnu
# Alternate location for some distros
ALT_INSTALL_DIR = /usr/lib/x86_64-linux-gnu

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	@echo "Installing NSS module..."
	@# Try to detect the correct lib directory
	@if [ -d "$(INSTALL_DIR)" ]; then \
		install -m 0755 $(TARGET) $(INSTALL_DIR)/; \
		ln -sf $(INSTALL_DIR)/$(TARGET) $(INSTALL_DIR)/$(SONAME_LINK); \
		echo "Installed to $(INSTALL_DIR)"; \
	elif [ -d "$(ALT_INSTALL_DIR)" ]; then \
		install -m 0755 $(TARGET) $(ALT_INSTALL_DIR)/; \
		ln -sf $(ALT_INSTALL_DIR)/$(TARGET) $(ALT_INSTALL_DIR)/$(SONAME_LINK); \
		echo "Installed to $(ALT_INSTALL_DIR)"; \
	elif [ -d "/lib64" ]; then \
		install -m 0755 $(TARGET) /lib64/; \
		ln -sf /lib64/$(TARGET) /lib64/$(SONAME_LINK); \
		echo "Installed to /lib64"; \
	else \
		install -m 0755 $(TARGET) /lib/; \
		ln -sf /lib/$(TARGET) /lib/$(SONAME_LINK); \
		echo "Installed to /lib"; \
	fi
	@echo "NSS module installed successfully"

uninstall:
	@echo "Uninstalling NSS module..."
	@rm -f $(INSTALL_DIR)/$(TARGET) $(INSTALL_DIR)/$(SONAME_LINK) \
	       $(ALT_INSTALL_DIR)/$(TARGET) $(ALT_INSTALL_DIR)/$(SONAME_LINK) \
	       /lib64/$(TARGET) /lib64/$(SONAME_LINK) \
	       /lib/$(TARGET) /lib/$(SONAME_LINK)
	@echo "NSS module uninstalled"
