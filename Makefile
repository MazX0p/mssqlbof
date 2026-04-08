# MSSQLBOF — build system
#
# Targets:
#   make            Cross-compile all BOFs to x64+x86 COFFs and build Linux test .so
#   make bofs       Just BOFs
#   make tds        Just Linux test .so
#   make test       Run pytest against Dockerized SQL Server
#   make clean

CC_X64    = x86_64-w64-mingw32-gcc
CC_X86    = i686-w64-mingw32-gcc
LD_X64    = x86_64-w64-mingw32-ld
LD_X86    = i686-w64-mingw32-ld
LINUX_CC  = gcc

CFLAGS_BOF = -Os -nostdlib -fno-asynchronous-unwind-tables -fno-stack-protector \
             -mno-stack-arg-probe -fno-builtin \
             -masm=intel -Wall -Wno-unused-parameter -Wno-pointer-sign \
             -Wno-incompatible-pointer-types \
             -Isrc/bof_compat -Isrc/common -Isrc/tds -DUNICODE -D_UNICODE

CFLAGS_LINUX = -Wall -Wno-unused-parameter -Wno-pointer-sign \
               -fPIC -g -O0 -Isrc/tds -Isrc/common -DTDS_LINUX_TEST

BOFS  ?= mssql
BUILD  = build

# Linux test library — uses OpenSSL stub for TLS, SQL auth for "login"
TDS_LINUX_SRCS = src/tds/packet.c \
                 src/tds/prelogin.c \
                 src/tds/tls_openssl.c \
                 src/tds/login7.c \
                 src/tds/sqlbatch.c \
                 src/tds/tokens.c \
                 src/tds/result.c \
                 src/tds/connect.c

TDS_LINUX_LIBS = -lssl -lcrypto

# Windows BOF library — Schannel TLS + SSPI Negotiate (current thread token)
TDS_BOF_SRCS = src/tds/packet.c \
               src/tds/prelogin.c \
               src/tds/tls_schannel.c \
               src/tds/sspi.c \
               src/tds/ntlm_pth.c \
               src/tds/login7.c \
               src/tds/sqlbatch.c \
               src/tds/tokens.c \
               src/tds/result.c \
               src/tds/connect.c \
               src/common/args.c

.PHONY: all bofs tds test clean dirs

all: bofs tds

dirs:
	@mkdir -p $(BUILD)

bofs: dirs $(foreach b,$(BOFS),$(BUILD)/$(b).x64.o $(BUILD)/$(b).x86.o)

# Single unified BOF — mssql.x64.o / mssql.x86.o. The BOF source plus
# every TDS library .c compile separately, then `ld -r` merges them into
# one relocatable COFF that the BOF loader resolves at runtime.
TDS_BOF_X64_OBJS = $(patsubst %.c,$(BUILD)/x64/%.o,$(TDS_BOF_SRCS))
TDS_BOF_X86_OBJS = $(patsubst %.c,$(BUILD)/x86/%.o,$(TDS_BOF_SRCS))

$(BUILD)/x64/%.o: %.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X64) $(CFLAGS_BOF) -c $< -o $@

$(BUILD)/x86/%.o: %.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X86) $(CFLAGS_BOF) -c $< -o $@

$(BUILD)/x64/bof_mssql.o: src/bofs/mssql.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X64) $(CFLAGS_BOF) -c $< -o $@
$(BUILD)/x86/bof_mssql.o: src/bofs/mssql.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X86) $(CFLAGS_BOF) -c $< -o $@

$(BUILD)/mssql.x64.o: $(BUILD)/x64/bof_mssql.o $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql.x86.o: $(BUILD)/x86/bof_mssql.o $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^

tds: dirs $(BUILD)/libtds.so

$(BUILD)/libtds.so: $(TDS_LINUX_SRCS) src/tds/tds.h src/tds/tds_internal.h | dirs
	$(LINUX_CC) $(CFLAGS_LINUX) -shared -o $@ $(TDS_LINUX_SRCS) $(TDS_LINUX_LIBS)


clean:
	rm -rf $(BUILD)
