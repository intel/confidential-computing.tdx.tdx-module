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

# proj_defs.mk - Project related definitions

PROJ_FLAGS =

FAULT_SAFE_MAGIC_INDICATOR=0xFF0F0F0F0F0F0FFF
PROJ_FLAGS += -DFAULT_SAFE_MAGIC_INDICATOR=$(FAULT_SAFE_MAGIC_INDICATOR)

STACK_PROTECTOR_OFFSET = 264
PROJ_FLAGS += -DSTACK_PROTECTOR_OFFSET=$(STACK_PROTECTOR_OFFSET)


################################################################
## Versioning

ifdef TDX_MODULE_BUILD_DATE
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(TDX_MODULE_BUILD_DATE)
else # TDX_MODULE_BUILD_DATE
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(shell date +%Y%m%d)
endif # TDX_MODULE_BUILD_DATE

ifdef TDX_MODULE_BUILD_NUM
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=$(TDX_MODULE_BUILD_NUM)
else # TDX_MODULE_BUILD_NUM
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=0
endif # TDX_MODULE_BUILD_NUM

ifdef TDX_MODULE_INTERNAL_VER
PROJ_FLAGS += -DTDX_MODULE_INTERNAL_VER=$(TDX_MODULE_INTERNAL_VER)
else # TDX_MODULE_INTERNAL_VER
PROJ_FLAGS += -DTDX_MODULE_INTERNAL_VER=4
endif # TDX_MODULE_INTERNAL_VER

ifdef TDX_MODULE_SEAM_MINOR_SVN
 PROJ_FLAGS += -DTDX_MINOR_SEAM_SVN=$(TDX_MODULE_SEAM_MINOR_SVN)
else # TDX_MODULE_SEAM_MINOR_SVN
 PROJ_FLAGS += -DTDX_MINOR_SEAM_SVN=15
endif # TDX_MODULE_SEAM_MINOR_SVN

 ########################################
 PROJ_FLAGS += -DTDX_MODULE_MAJOR_VER=1
 PROJ_FLAGS += -DTDX_MODULE_MINOR_VER=5
 PROJ_FLAGS += -DTDX_MODULE_UPDATE_VER=36
 ########################################


################################################################

################################################################
## TDX features

# Default features
PROJ_FLAGS += -DNO_SPEC_CTRL_VIRT_SUPPORT
PROJ_FLAGS += -DDYNAMIC_PAMT_SUPPORT
PROJ_FLAGS += -DHSD_18042345067_WA # https://hsdes.intel.com/appstore/article/#/18042345067
 PROJ_FLAGS += -DINTR_STATE_SUPPORTED

 PROJ_FLAGS += -DVEINFO_INTR_STATE_SUPPORTED

PROJ_FLAGS += -DTD_MIGRATION_SUPPORTED

PROJ_FLAGS += -DTD_PART_MIGRATION_SUPPORTED

PROJ_FLAGS += -DNON_BLOCKING_EXPORT_SUPPORTED
PROJ_FLAGS += -DNBE_EXPORT_RESTORE_SUPPORTED


 PROJ_FLAGS += -DTDID_VMID_REPORTING_SUPPORTED

 PROJ_FLAGS += -DSEALING_SUPPORTED


################################################################

################################################################
## Debug features


ifdef DBG_TRACE
PROJ_FLAGS += -DDEBUGFEATURE_TDX_DBG_TRACE
endif # DBG_TRACE


################################################################

################################################################
## Miscellaneous features


PROJ_FLAGS += -D_NO_IPP_DEPRECATED

################################################################

################################################################
PRODUCTION_FLAGS =

################################################################


# Architecture git data
################################################################
    COMMIT_ID = ad4633b
    ARCHITECTURE_BRANCH_NAME = TDX_Module_1.5.36_v0.990
    CPUID_EXCEL_VERSION_SUPPORTED = 10
    MSR_EXCEL_VERSION_SUPPORTED = 6
    TDVPS_EXCEL_VERSION_SUPPORTED = 28
    TDR_TDCS_EXCEL_VERSION_SUPPORTED = 25
    TD_VMCS_EXCEL_VERSION_SUPPORTED = 26
    GLOBAL_SYS_EXCEL_VERSION_SUPPORTED = 2
    ERRORS_VERSION_SUPPORTED = 5
    OP_STATE_VERSION_SUPPORTED = 5
    SEPT_STATE_VERSION_SUPPORTED = 9
    L2_VMCS_VERSION_SUPPORTED = 25
    FEATURES_EXCEL_VERSION_SUPPORTED = 0
    HANDOFF_EXCEL_VERSION_SUPPORTED = 0
################################################################
################################################################
################################################################
