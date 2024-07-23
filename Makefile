# Variables
VERSION := 0.68
OUT := redsocks2
OS := $(shell uname)
CFLAGS := -fPIC -O3
LIBS := -levent
CONF := config.h
DEPS := .depend
CRYPTO := OpenSSL

# Define OpenSSL and other directories
OPENSSL_DIR := /usr/local/openssl-1.0.2
INCLUDE_DIRS := $(OPENSSL_DIR)/include
LIB_DIRS := $(OPENSSL_DIR)/lib

ifeq ($(OS), FreeBSD)
INCLUDE_DIRS += /usr/local/include
LIB_DIRS += /usr/local/lib
endif

ifeq ($(OS), OpenBSD)
INCLUDE_DIRS += /usr/local/include
LIB_DIRS += /usr/local/lib
endif

ifdef USE_CRYPTO_POLARSSL
CRYPTO := PolarSSL
LIBS += -lpolarssl
CFLAGS += -DUSE_CRYPTO_POLARSSL
$(info Compile with PolarSSL.)
else
LIBS += -lssl -lcrypto
CFLAGS += -DUSE_CRYPTO_OPENSSL
endif

ifdef ENABLE_HTTPS_PROXY
LIBS += -levent_openssl
CFLAGS += -DENABLE_HTTPS_PROXY
$(info Compile with HTTPS proxy enabled.)
endif

ifdef ENABLE_STATIC
LIBS += -lz
LDFLAGS += -Wl,-static -static -static-libgcc -s
endif

# Compiler and linker flags
override CFLAGS += -D_BSD_SOURCE -D_DEFAULT_SOURCE -Wall
override CFLAGS += -std=c99
override CFLAGS += -I$(INCLUDE_DIRS)
override LDFLAGS += -L$(LIB_DIRS)

# Source files and objects
SRCS := $(OBJS:.o=.c)
OBJS := parser.o main.o redsocks.o log.o direct.o ipcache.o autoproxy.o \
        encrypt.o shadowsocks.o http-connect.o socks4.o socks5.o http-relay.o \
        base.o base64.o md5.o http-auth.o utils.o redudp.o socks5-udp.o \
        tcpdns.o gen/version.o

ifdef ENABLE_HTTPS_PROXY
OBJS += https-connect.o $(OBJS)
endif
# Targets
all: $(OUT)

.PHONY: all clean distclean tags

tags: *.c *.h
	ctags -R

$(CONF):
	@case $(OS) in \
	Linux*) \
		echo "#define USE_IPTABLES" >$(CONF) \
		;; \
	FreeBSD|OpenBSD|NetBSD) \
		echo "#define USE_PF" >$(CONF) \
		;; \
	*) \
		echo "Unknown system, only generic firewall code is compiled" 1>&2; \
		echo "/* Unknown system, only generic firewall code is compiled */" >$(CONF) \
		;; \
	esac

gen/version.c: *.c *.h gen/.build
	$(RM) -f $@.tmp
	echo '/* this file is auto-generated during build */' > $@.tmp
	echo '#include "../version.h"' >> $@.tmp
	echo 'const char* redsocks_version = ' >> $@.tmp
	if [ -d .git ]; then \
		echo '"redsocks.git/'`git describe --tags`' $(CRYPTO)"'; \
		if [ `git status --porcelain | grep -v -c '^??'` != 0 ]; then \
			echo '"-unclean"'; \
		fi; \
		echo '"\\n"'; \
		echo '"Features: $(FEATURES)"'; \
	else \
		echo '"redsocks/$(VERSION) $(CRYPTO)"'; \
		echo '"\\n"'; \
		echo '"Features: $(FEATURES)"'; \
	fi >> $@.tmp
	echo ';' >> $@.tmp
	mv -f $@.tmp $@

gen/.build:
	mkdir -p gen
	touch $@

base.c: $(CONF)

$(DEPS): $(SRCS)
	$(CC) -MM $(CFLAGS) $(SRCS) 2>/dev/null >$(DEPS) || \
	( \
		for I in $(wildcard *.h); do \
			export $${I//[-.]/_}_DEPS="`sed '/^\#[ \t]*include \?"\(.*\)".*/!d;s//\1/' $$I`"; \
		done; \
		echo -n >$(DEPS); \
		for SRC in $(SRCS); do \
			echo -n "$${SRC%.c}.o: " >>$(DEPS); \
			export SRC_DEPS="`sed '/\#[ \t]*include \?"\(.*\)".*/!d;s//\1/' $$SRC | sort`"; \
			while true; do \
				export SRC_DEPS_OLD="$$SRC_DEPS"; \
				export SRC_DEEP_DEPS=""; \
				for HDR in $$SRC_DEPS; do \
					eval export SRC_DEEP_DEPS="\"$$SRC_DEEP_DEPS \$$$${HDR//[-.]/_}_DEPS\""; \
				done; \
				export SRC_DEPS="`echo $$SRC_DEPS $$SRC_DEEP_DEPS | sed 's/  */\n/g' | sort -u`"; \
				test "$$SRC_DEPS" = "$$SRC_DEPS_OLD" && break; \
			done; \
			echo $$SRC $$SRC_DEPS >>$(DEPS); \
		done; \
	)

-include $(DEPS)

$(OUT): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(CONF) $(OBJS)

distclean: clean
	$(RM) $(OUT)
	$(RM) tags $(DEPS)
	$(RM) -r gen
