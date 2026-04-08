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

BOFS  ?= mssql mssql_hello mssql_find mssql_info mssql_query mssql_links mssql_exec mssql_impersonate
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

# Each BOF compiles its own .c + all TDS lib .c files separately, then
# `ld -r` merges them into a single relocatable COFF that the BOF loader
# resolves at runtime. The bof_template hello BOF doesn't need TDS, so
# special-case it.
TDS_BOF_X64_OBJS = $(patsubst %.c,$(BUILD)/x64/%.o,$(TDS_BOF_SRCS))
TDS_BOF_X86_OBJS = $(patsubst %.c,$(BUILD)/x86/%.o,$(TDS_BOF_SRCS))

$(BUILD)/x64/%.o: %.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X64) $(CFLAGS_BOF) -c $< -o $@

$(BUILD)/x86/%.o: %.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X86) $(CFLAGS_BOF) -c $< -o $@

# Hello BOF: standalone, no TDS
$(BUILD)/mssql_hello.x64.o: src/bofs/mssql_hello.c | dirs
	$(CC_X64) $(CFLAGS_BOF) -c $< -o $@
$(BUILD)/mssql_hello.x86.o: src/bofs/mssql_hello.c | dirs
	$(CC_X86) $(CFLAGS_BOF) -c $< -o $@

# Real BOFs: BOF + TDS lib + helpers, merged into one COFF
$(BUILD)/x64/bof_%.o: src/bofs/%.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X64) $(CFLAGS_BOF) -c $< -o $@
$(BUILD)/x86/bof_%.o: src/bofs/%.c | dirs
	@mkdir -p $(dir $@)
	$(CC_X86) $(CFLAGS_BOF) -c $< -o $@

$(BUILD)/mssql.x64.o:             $(BUILD)/x64/bof_mssql.o             $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql.x86.o:             $(BUILD)/x86/bof_mssql.o             $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_find.x64.o:        $(BUILD)/x64/bof_mssql_find.o        $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_find.x86.o:        $(BUILD)/x86/bof_mssql_find.o        $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_info.x64.o:        $(BUILD)/x64/bof_mssql_info.o        $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_info.x86.o:        $(BUILD)/x86/bof_mssql_info.o        $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_query.x64.o:       $(BUILD)/x64/bof_mssql_query.o       $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_query.x86.o:       $(BUILD)/x86/bof_mssql_query.o       $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_links.x64.o:       $(BUILD)/x64/bof_mssql_links.o       $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_links.x86.o:       $(BUILD)/x86/bof_mssql_links.o       $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_exec.x64.o:        $(BUILD)/x64/bof_mssql_exec.o        $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_exec.x86.o:        $(BUILD)/x86/bof_mssql_exec.o        $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^
$(BUILD)/mssql_impersonate.x64.o: $(BUILD)/x64/bof_mssql_impersonate.o $(TDS_BOF_X64_OBJS) ; $(LD_X64) -r -o $@ $^
$(BUILD)/mssql_impersonate.x86.o: $(BUILD)/x86/bof_mssql_impersonate.o $(TDS_BOF_X86_OBJS) ; $(LD_X86) -r -o $@ $^

tds: dirs $(BUILD)/libtds.so

$(BUILD)/libtds.so: $(TDS_LINUX_SRCS) src/tds/tds.h src/tds/tds_internal.h | dirs
	$(LINUX_CC) $(CFLAGS_LINUX) -shared -o $@ $(TDS_LINUX_SRCS) $(TDS_LINUX_LIBS)

test: tds
	cd tests && python3 -m pytest -v

clean:
	rm -rf $(BUILD)
