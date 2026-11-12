// Copyright (C) 2023 Intel Corporation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
// OR OTHER DEALINGS IN THE SOFTWARE.
//
// SPDX-License-Identifier: MIT

/**
 * @file fatal_info.h
 * @brief fatal error info structures for diagnostics
 */

#ifndef SRC_COMMON_HELPERS_FATAL_ERROR_H_
#define SRC_COMMON_HELPERS_FATAL_ERROR_H_

#include "tdx_api_defs.h"
#include "x86_defs/x86_defs.h"
//#include "memory_handlers/pamt_manager.h"

#define HPA_CODE_NO_LOGGING_REQUIRED 0x3FFFFFFFFFFF

typedef enum PACKED
{
    /* 0x0 : FATAL_INFO does not contain valid information. The host VMM should initialize this field to 0.
       0x1 : Information is being written by P-SEAMLDR or TDX module.
       0xFE: FATAL_INFO contains valid P-SEAMLDR fatal error information.
       0xFF: FATAL_INFO contains valid TDX module fatal error information. */

    FATAL_INFO_STATE_NO_INFO             = 0x0,
    FATAL_INFO_STATE_WRITING_IN_PROGRESS = 0x1,
    FATAL_INFO_STATE_PSMLDR_VALID_INFO   = 0xFE,
    FATAL_INFO_STATE_TDX_VALID_INFO      = 0xFF
}fatal_info_state_e;

typedef enum PACKED
{
    /* 0x0: Basic information only.
       0x1: Information for TD-specific errors:  basic information + TD handle.
       0x2: Information for Secure EPT related errors (with TD handle).
       0x3: Information for Secure EPT related errors (with EPTP).
       0x4: Information for page HPA related errors.
       0x5: Information for PAMT related errors.
       0x6: Information for an unexpected exception.
       0x7: Information for an unexpected VM exit. */

    FATAL_INFO_FORMAT_BASIC_INFO                = 0x0,
    FATAL_INFO_FORMAT_TD_HANDLE_INFO            = 0x1,
    FATAL_INFO_FORMAT_SEPT_TD_HANDLE_INFO       = 0x2,
    FATAL_INFO_FORMAT_SEPT_EPTP_INFO            = 0x3,
    FATAL_INFO_FORMAT_PAGE_HPA_INFO             = 0x4,
    // FATAL_INFO_FORMAT_PAMT_INFO                 = 0x5,
    FATAL_INFO_FORMAT_UNEXPECTED_EXCEPTION_INFO = 0x6,
    FATAL_INFO_FORMAT_UNEXPECTED_VM_EXIT_INFO   = 0x7
}fatal_info_format_e;

typedef union fatal_info_sept_u
{
    struct // td_and_vm_s
    {
        uint64_t reserved_0  : 12; // Bits  0:11
        uint64_t tdr_hpa     : 40; // Bits 12:51
        uint64_t vm_index    :  2; // Bits 52:53
        uint64_t reserved_1  : 10; // Bits 54:63
    };

    struct // gpa_and_level_s
    {
        uint64_t offending_sept_entry_level :  3; // Bits  0: 2
        uint64_t reserved_2                 :  9; // Bits  3:11
        uint64_t offending_gpa              : 40; // Bits 12:51
        uint64_t reserved_3                 : 12; // Bits 52:63
    };

    uint8_t raw[8];
} fatal_info_sept_t;
tdx_static_assert(sizeof(fatal_info_sept_t) == 8, fatal_info_sept_t);

typedef union basic_fatal_info_u
{
    struct // basic_info_s
    {
        fatal_info_state_e state;
        fatal_info_format_e format;
        uint16_t reserved_0;
        uint32_t x2apic_id;
        uint64_t error_id;
    };

    uint8_t raw[16];
} basic_fatal_info_t;
tdx_static_assert(sizeof(basic_fatal_info_t) == 16, basic_fatal_info_t);

typedef union extended_fatal_info_u
{
    struct // td_handle_s
    {
        td_handle_and_flags_t td_handle;
        uint8_t reserved_0[40];
    };

    struct // sept_td_handle_s
    {
        fatal_info_sept_t td_and_vm;
        fatal_info_sept_t gpa_and_level;
        ia32e_sept_t sept_entry;
        uint8_t reserved_1[24];
    };

    struct // sept_eptp_s
    {
        uint64_t eptp;
        fatal_info_sept_t gpa_and_level_0;
        ia32e_sept_t sept_entry_0;
        uint8_t reserved_2[24];
    };

    struct // page_hpa_s
    {
        uint64_t hpa;
        uint8_t size;
        uint8_t reserved_3[39];
    };

    // currently not in use
    /*struct // pamt_s
    {
        pamt_entry_t pamt_entry;
        uint64_t hpa_0;
        uint8_t level;
        uint8_t reserved_4[7];
        uint64_t pamt_page;
        uint8_t reserved_5[8];
    };*/

    struct // vector_s
    {
        uint8_t vector;
        uint8_t reserved_6[47];
    };

    struct // unexpected_vm_exit_s
    {
        fatal_info_sept_t td_and_vm_0;
        uint32_t exit_reason;
        uint32_t extended_info;
        uint8_t reserved_5[32];
    };

    uint8_t raw[48];
} extended_fatal_info_t;
tdx_static_assert(sizeof(extended_fatal_info_t) == 48, extended_fatal_info_t);

typedef struct PACKED fatal_info_u
{
    union
    {
        struct
        {
            basic_fatal_info_t basic_info;
            extended_fatal_info_t extended_info;
        };

        uint8_t raw[64];
    };
} fatal_info_t;
tdx_static_assert(sizeof(fatal_info_t) == 64, fatal_info_t);

typedef union fatal_error_config_u
{
    struct
    {
        uint64_t reserved_0          :  6; // Bits 0:5
        uint64_t fatal_info_hpa      : 46; // Bits 6:51
        uint64_t reserved_1          :  2; // Bits 52:53
        uint64_t notification_intr   :  2; // Bits 54:55
        uint64_t notification_vector :  8; // Bits 56:63
    };

    uint64_t raw;
}fatal_error_config_t;
tdx_static_assert(sizeof(fatal_error_config_t) == 8, fatal_error_config_t);

typedef enum
{
    FATAL_ERROR_ID_0 = 0,
    FATAL_ERROR_ID_1,
    FATAL_ERROR_ID_2,
    FATAL_ERROR_ID_3,
    FATAL_ERROR_ID_4,
    FATAL_ERROR_ID_5,
    FATAL_ERROR_ID_6,
    FATAL_ERROR_ID_7,
    FATAL_ERROR_ID_8,
    FATAL_ERROR_ID_9,
    FATAL_ERROR_ID_10,
    FATAL_ERROR_ID_11,
    FATAL_ERROR_ID_12,
    FATAL_ERROR_ID_13,
    FATAL_ERROR_ID_14,
    FATAL_ERROR_ID_15,
    FATAL_ERROR_ID_16,
    FATAL_ERROR_ID_17,
    FATAL_ERROR_ID_18,
    FATAL_ERROR_ID_19,
    FATAL_ERROR_ID_20,
    FATAL_ERROR_ID_21,
    FATAL_ERROR_ID_22,
    FATAL_ERROR_ID_23,
    FATAL_ERROR_ID_24,
    FATAL_ERROR_ID_25,
    FATAL_ERROR_ID_26,
    FATAL_ERROR_ID_27,
    FATAL_ERROR_ID_28,
    FATAL_ERROR_ID_29,
    FATAL_ERROR_ID_30,
    FATAL_ERROR_ID_31,
    FATAL_ERROR_ID_32,
    FATAL_ERROR_ID_33,
    FATAL_ERROR_ID_34,
    FATAL_ERROR_ID_35,
    FATAL_ERROR_ID_36,
    FATAL_ERROR_ID_37,
    FATAL_ERROR_ID_38,
    FATAL_ERROR_ID_39,
    FATAL_ERROR_ID_40,
    FATAL_ERROR_ID_41,
    FATAL_ERROR_ID_42,
    FATAL_ERROR_ID_43,
    FATAL_ERROR_ID_44,
    FATAL_ERROR_ID_45,
    FATAL_ERROR_ID_46,
    FATAL_ERROR_ID_47,
    FATAL_ERROR_ID_48,
    FATAL_ERROR_ID_49,
    FATAL_ERROR_ID_50,
    FATAL_ERROR_ID_51,
    FATAL_ERROR_ID_52,
    FATAL_ERROR_ID_53,
    FATAL_ERROR_ID_54,
    FATAL_ERROR_ID_55,
    FATAL_ERROR_ID_56,
    FATAL_ERROR_ID_57,
    FATAL_ERROR_ID_58,
    FATAL_ERROR_ID_59,
    FATAL_ERROR_ID_60,
    FATAL_ERROR_ID_61,
    FATAL_ERROR_ID_62,
    FATAL_ERROR_ID_63,
    FATAL_ERROR_ID_64,
    FATAL_ERROR_ID_65,
    FATAL_ERROR_ID_66,
    FATAL_ERROR_ID_67,
    FATAL_ERROR_ID_68,
    FATAL_ERROR_ID_69,
    FATAL_ERROR_ID_70,
    FATAL_ERROR_ID_71,
    FATAL_ERROR_ID_72,
    FATAL_ERROR_ID_73,
    FATAL_ERROR_ID_74,
    FATAL_ERROR_ID_75,
    FATAL_ERROR_ID_76,
    FATAL_ERROR_ID_77,
    FATAL_ERROR_ID_78,
    FATAL_ERROR_ID_79,
    FATAL_ERROR_ID_80,
    FATAL_ERROR_ID_81,
    FATAL_ERROR_ID_82,
    FATAL_ERROR_ID_83,
    FATAL_ERROR_ID_84,
    FATAL_ERROR_ID_85,
    FATAL_ERROR_ID_86,
    FATAL_ERROR_ID_87,
    FATAL_ERROR_ID_88,
    FATAL_ERROR_ID_89,
    FATAL_ERROR_ID_90,
    FATAL_ERROR_ID_91,
    FATAL_ERROR_ID_92,
    FATAL_ERROR_ID_93,
    FATAL_ERROR_ID_94,
    FATAL_ERROR_ID_95,
    FATAL_ERROR_ID_96,
    FATAL_ERROR_ID_97,
    FATAL_ERROR_ID_98,
    FATAL_ERROR_ID_99,
    FATAL_ERROR_ID_100,
    FATAL_ERROR_ID_101,
    FATAL_ERROR_ID_102,
    FATAL_ERROR_ID_103,
    FATAL_ERROR_ID_104,
    FATAL_ERROR_ID_105,
    FATAL_ERROR_ID_106,
    FATAL_ERROR_ID_107,
    FATAL_ERROR_ID_108,
    FATAL_ERROR_ID_109,
    FATAL_ERROR_ID_110,
    FATAL_ERROR_ID_111,
    FATAL_ERROR_ID_112,
    FATAL_ERROR_ID_113,
    FATAL_ERROR_ID_114,
    FATAL_ERROR_ID_115,
    FATAL_ERROR_ID_116,
    FATAL_ERROR_ID_117,
    FATAL_ERROR_ID_118,
    FATAL_ERROR_ID_119,
    FATAL_ERROR_ID_120,
    FATAL_ERROR_ID_121,
    FATAL_ERROR_ID_122,
    FATAL_ERROR_ID_123,
    FATAL_ERROR_ID_124,
    FATAL_ERROR_ID_125,
    FATAL_ERROR_ID_126,
    FATAL_ERROR_ID_127,
    FATAL_ERROR_ID_128,
    FATAL_ERROR_ID_129,
    FATAL_ERROR_ID_130,
    FATAL_ERROR_ID_131,
    FATAL_ERROR_ID_132,
    FATAL_ERROR_ID_133,
    FATAL_ERROR_ID_134,
    FATAL_ERROR_ID_135,
    FATAL_ERROR_ID_136,
    FATAL_ERROR_ID_137,
    FATAL_ERROR_ID_138,
    FATAL_ERROR_ID_139,
    FATAL_ERROR_ID_140,
    FATAL_ERROR_ID_141,
    FATAL_ERROR_ID_142,
    FATAL_ERROR_ID_143,
    FATAL_ERROR_ID_144,
    FATAL_ERROR_ID_145,
    FATAL_ERROR_ID_146,
    FATAL_ERROR_ID_147,
    FATAL_ERROR_ID_148,
    FATAL_ERROR_ID_149,
    FATAL_ERROR_ID_150,
    FATAL_ERROR_ID_151,
    FATAL_ERROR_ID_152,
    FATAL_ERROR_ID_153,
    FATAL_ERROR_ID_154,
    FATAL_ERROR_ID_155,
    FATAL_ERROR_ID_156,
    FATAL_ERROR_ID_157,
    FATAL_ERROR_ID_158,
    FATAL_ERROR_ID_159,
    FATAL_ERROR_ID_160,
    FATAL_ERROR_ID_161,
    FATAL_ERROR_ID_162,
    FATAL_ERROR_ID_163,
    FATAL_ERROR_ID_164,
    FATAL_ERROR_ID_165,
    FATAL_ERROR_ID_166,
    FATAL_ERROR_ID_167,
    FATAL_ERROR_ID_168,
    FATAL_ERROR_ID_169,
    FATAL_ERROR_ID_170,
    FATAL_ERROR_ID_171,
    FATAL_ERROR_ID_172,
    FATAL_ERROR_ID_173,
    FATAL_ERROR_ID_174,
    FATAL_ERROR_ID_175,
    FATAL_ERROR_ID_176,
    FATAL_ERROR_ID_177,
    FATAL_ERROR_ID_178,
    FATAL_ERROR_ID_179,
    FATAL_ERROR_ID_180,
    FATAL_ERROR_ID_181,
    FATAL_ERROR_ID_182,
    FATAL_ERROR_ID_183,
    FATAL_ERROR_ID_184,
    FATAL_ERROR_ID_185,
    FATAL_ERROR_ID_186,
    FATAL_ERROR_ID_187,
    FATAL_ERROR_ID_188,
    FATAL_ERROR_ID_189,
    FATAL_ERROR_ID_190,
    FATAL_ERROR_ID_191,
    FATAL_ERROR_ID_192,
    FATAL_ERROR_ID_193,
    FATAL_ERROR_ID_194,
    FATAL_ERROR_ID_195,
    FATAL_ERROR_ID_196,
    FATAL_ERROR_ID_197,
    FATAL_ERROR_ID_198,
    FATAL_ERROR_ID_199,
    FATAL_ERROR_ID_200,
    FATAL_ERROR_ID_201,
    FATAL_ERROR_ID_202,
    FATAL_ERROR_ID_203,
    FATAL_ERROR_ID_204,
    FATAL_ERROR_ID_205,
    FATAL_ERROR_ID_206,
    FATAL_ERROR_ID_207,
    FATAL_ERROR_ID_208,
    FATAL_ERROR_ID_209,
    FATAL_ERROR_ID_210,
    FATAL_ERROR_ID_211,
    FATAL_ERROR_ID_212,
    FATAL_ERROR_ID_213,
    FATAL_ERROR_ID_214,
    FATAL_ERROR_ID_215,
    FATAL_ERROR_ID_216,
    FATAL_ERROR_ID_217,
    FATAL_ERROR_ID_218,
    FATAL_ERROR_ID_219,
    FATAL_ERROR_ID_220,
    FATAL_ERROR_ID_221,
    FATAL_ERROR_ID_222,
    FATAL_ERROR_ID_223,
    FATAL_ERROR_ID_224,
    FATAL_ERROR_ID_225,
    FATAL_ERROR_ID_226,
    FATAL_ERROR_ID_227,
    FATAL_ERROR_ID_228,
    FATAL_ERROR_ID_229,
    FATAL_ERROR_ID_230,
    FATAL_ERROR_ID_231,
    FATAL_ERROR_ID_232,
    FATAL_ERROR_ID_233,
    FATAL_ERROR_ID_234,
    FATAL_ERROR_ID_235,
    FATAL_ERROR_ID_236,
    FATAL_ERROR_ID_237,
    FATAL_ERROR_ID_238,
    FATAL_ERROR_ID_239,
    FATAL_ERROR_ID_240,
    FATAL_ERROR_ID_241,
    FATAL_ERROR_ID_242,
    FATAL_ERROR_ID_243,
    FATAL_ERROR_ID_244,
    FATAL_ERROR_ID_245,
    FATAL_ERROR_ID_246,
    FATAL_ERROR_ID_247,
    FATAL_ERROR_ID_248,
    FATAL_ERROR_ID_249,
    FATAL_ERROR_ID_250,
    FATAL_ERROR_ID_251,
    FATAL_ERROR_ID_252,
    FATAL_ERROR_ID_253,
    FATAL_ERROR_ID_254,
    FATAL_ERROR_ID_255,
    FATAL_ERROR_ID_256,
    FATAL_ERROR_ID_257,
    FATAL_ERROR_ID_258,
    FATAL_ERROR_ID_259,
    FATAL_ERROR_ID_260,
    FATAL_ERROR_ID_261,
    FATAL_ERROR_ID_262,
    FATAL_ERROR_ID_263,
    FATAL_ERROR_ID_264,
    FATAL_ERROR_ID_265,
    FATAL_ERROR_ID_266,
    FATAL_ERROR_ID_267,
    FATAL_ERROR_ID_268,
    FATAL_ERROR_ID_269,
    FATAL_ERROR_ID_270,
    FATAL_ERROR_ID_271,
    FATAL_ERROR_ID_272,
    FATAL_ERROR_ID_273,
    FATAL_ERROR_ID_274,
    FATAL_ERROR_ID_275,
    FATAL_ERROR_ID_276,
    FATAL_ERROR_ID_277,
    FATAL_ERROR_ID_278,
    FATAL_ERROR_ID_279,
    FATAL_ERROR_ID_280,
    FATAL_ERROR_ID_281,
    FATAL_ERROR_ID_282,
    FATAL_ERROR_ID_283,
    FATAL_ERROR_ID_284,
    FATAL_ERROR_ID_285,
    FATAL_ERROR_ID_286,
    FATAL_ERROR_ID_287,
    FATAL_ERROR_ID_288,
    FATAL_ERROR_ID_289,
    FATAL_ERROR_ID_290,
    FATAL_ERROR_ID_291,
    FATAL_ERROR_ID_292,
    FATAL_ERROR_ID_293,
    FATAL_ERROR_ID_294,
    FATAL_ERROR_ID_295,
    FATAL_ERROR_ID_296,
    FATAL_ERROR_ID_297,
    FATAL_ERROR_ID_298,
    FATAL_ERROR_ID_299,
    FATAL_ERROR_ID_300,
    FATAL_ERROR_ID_301,
    FATAL_ERROR_ID_302,
    FATAL_ERROR_ID_303,
    FATAL_ERROR_ID_304,
    FATAL_ERROR_ID_305,
    FATAL_ERROR_ID_306,
    FATAL_ERROR_ID_307,
    FATAL_ERROR_ID_308,
    FATAL_ERROR_ID_309,
    FATAL_ERROR_ID_310,
    FATAL_ERROR_ID_311,
    FATAL_ERROR_ID_312,
    FATAL_ERROR_ID_313,
    FATAL_ERROR_ID_314,
    FATAL_ERROR_ID_315,
    FATAL_ERROR_ID_316,
    FATAL_ERROR_ID_317,
    FATAL_ERROR_ID_318,
    FATAL_ERROR_ID_319,
    FATAL_ERROR_ID_320,
    FATAL_ERROR_ID_321,
    FATAL_ERROR_ID_322,
    FATAL_ERROR_ID_323,
    FATAL_ERROR_ID_324,
    FATAL_ERROR_ID_325,
    FATAL_ERROR_ID_326,
    FATAL_ERROR_ID_327,
    FATAL_ERROR_ID_328,
    FATAL_ERROR_ID_329,
    FATAL_ERROR_ID_330,
    FATAL_ERROR_ID_331,
    FATAL_ERROR_ID_332,
    FATAL_ERROR_ID_333,
    FATAL_ERROR_ID_334,
    FATAL_ERROR_ID_335,
    FATAL_ERROR_ID_336,
    FATAL_ERROR_ID_337,
    FATAL_ERROR_ID_338,
    FATAL_ERROR_ID_339,
    FATAL_ERROR_ID_340,
    FATAL_ERROR_ID_341,
    FATAL_ERROR_ID_342,
    FATAL_ERROR_ID_343,
    FATAL_ERROR_ID_344,
    FATAL_ERROR_ID_345,
    FATAL_ERROR_ID_346,
    FATAL_ERROR_ID_347,
    FATAL_ERROR_ID_348,
    FATAL_ERROR_ID_349,
    FATAL_ERROR_ID_350,
    FATAL_ERROR_ID_351,
    FATAL_ERROR_ID_352,
    FATAL_ERROR_ID_353,
    FATAL_ERROR_ID_354,
    FATAL_ERROR_ID_355,
    FATAL_ERROR_ID_356,
    FATAL_ERROR_ID_357,
    FATAL_ERROR_ID_358,
    FATAL_ERROR_ID_359,
    FATAL_ERROR_ID_360,
    FATAL_ERROR_ID_361,
    FATAL_ERROR_ID_362,
    FATAL_ERROR_ID_363,
    FATAL_ERROR_ID_364,
    FATAL_ERROR_ID_365,
    FATAL_ERROR_ID_366,
    FATAL_ERROR_ID_367,
    FATAL_ERROR_ID_368,
    FATAL_ERROR_ID_369,
    FATAL_ERROR_ID_370,
    FATAL_ERROR_ID_371,
    FATAL_ERROR_ID_372,
    FATAL_ERROR_ID_373,
    FATAL_ERROR_ID_374,
    FATAL_ERROR_ID_375,
    FATAL_ERROR_ID_376,
    FATAL_ERROR_ID_377,
    FATAL_ERROR_ID_378,
    FATAL_ERROR_ID_379,
    FATAL_ERROR_ID_380,
    FATAL_ERROR_ID_381,
    FATAL_ERROR_ID_382,
    FATAL_ERROR_ID_383,
    FATAL_ERROR_ID_384,
    FATAL_ERROR_ID_385,
    FATAL_ERROR_ID_386,
}fatal_error_id_e;

#endif /* SRC_COMMON_HELPERS_FATAL_ERROR_H_ */
