#// Copyright (C) 2023 Intel Corporation
#//
#// Permission is hereby granted, free of charge, to any person obtaining a copy
#// of this software and associated documentation files (the "Software"),
#// to deal in the Software without restriction, including without limitation
#// the rights to use, copy, modify, merge, publish, distribute, sublicense,
#// and/or sell copies of the Software, and to permit persons to whom
#// the Software is furnished to do so, subject to the following conditions:
#//
#// The above copyright notice and this permission notice shall be included
#// in all copies or substantial portions of the Software.
#//
#// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
#// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
#// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
#// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
#// OR OTHER DEALINGS IN THE SOFTWARE.
#//
#// SPDX-License-Identifier: MIT

# compiler_defs.mk - Compiler definition and flags

include proj_defs.mk

# Compiler
CC = clang-16
CXX = clang++-16
CCVERSION = $(shell $(CC) --version | grep 'clang version' | cut -f1 -d"." | sed 's/^.* //g' )

CC_WITHOUT_CODE_COVERAGE := $(CC)
CXX_WITHOUT_CODE_COVERAGE := $(CXX)

# Standard flags
STD_FLAGS = -MD -MP -m64 -Wall -Wextra -fPIC -fno-builtin-memset -fvisibility=hidden -mcmodel=small \
			-mstack-alignment=16 -mstackrealign -std=c17 -mno-mmx -mno-sse -fno-jump-tables
			
STD_FLAGS += -D__FILENAME__=\"$(lastword $(subst /, ,$<))\"

# Optimization flags
OPT_FLAGS = -Os

# SecV mandatory flags
SECV_FLAGS = -Wdouble-promotion -Wshadow -Wconversion -Wmissing-prototypes -Wpointer-arith -Wuninitialized -Wunreachable-code -Wunused-function -Werror -D_FORTIFY_SOURCE=2 -fno-zero-initialized-in-bss -fstack-protector-strong -Wformat -Wformat-security -Werror=format-security

CET_FLAGS = -mshstk -fcf-protection

STACK_PROTECTOR_FLAGS = -mstack-protector-guard-reg=gs -mstack-protector-guard-offset=$(STACK_PROTECTOR_OFFSET)

# Combined flags
CFLAGS_NO_STK_PRT = $(STD_FLAGS) $(PROJ_FLAGS) $(OPT_FLAGS) $(SECV_FLAGS) $(CET_FLAGS) $(PRODUCTION_FLAGS)
CFLAGS = $(CFLAGS_NO_STK_PRT) $(STACK_PROTECTOR_FLAGS)

# Entry pointer for the linker
MODULE_ENTRY_POINT = tdx_seamcall_entry_point

LINKER_SCRIPT = $(PROJ_DIR)/tdx_linker_script.lds

# Linker flags
LDFLAGS = -Wl,-shared -Wl,-pie -Wl,-e,$(MODULE_ENTRY_POINT) -Wl,-z,relro -Wl,-z,now -Wl,--wrap=__stack_chk_fail \
		  -disable-red-zone -nostartfiles -Wl,-T,$(LINKER_SCRIPT)

