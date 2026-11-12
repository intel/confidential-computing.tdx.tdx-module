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
 * @file tdx_locks.h
 * @brief TDX Locks Definitions
 */

#ifndef SRC_COMMON_HELPERS_TDX_LOCKS_H_
#define SRC_COMMON_HELPERS_TDX_LOCKS_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"

#include "tdx_api_defs.h"
#include "accessors/ia32_accessors.h"
#include "debug/tdx_debug.h"
#include "helpers/error_reporting.h"
#include "service_td.h"
#include TDX_ERROR_CODES_DEFS_HEADER

typedef enum
{
    TDX_LOCK_NO_LOCK = 0,
    TDX_LOCK_SHARED = 1,
    TDX_LOCK_EXCLUSIVE = 2
} lock_type_t;

typedef enum
{
    LOCK_RET_FAIL, LOCK_RET_SUCCESS, LOCK_RET_FAIL_HOST_PRIORITY
} lock_return_t;

typedef uint8_t mutex_lock_t;

typedef enum
{
    MUTEX_FREE = 0, MUTEX_LOCK = 1
} mutex_state_t;


_STATIC_INLINE_ lock_return_t acquire_mutex_lock(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval = _lock_cmpxchg_8bit(MUTEX_FREE, MUTEX_LOCK, lock_ptr);

    return (retval == MUTEX_FREE) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

#if defined(DEBUGFEATURE_TDX_DBG_TRACE)
_STATIC_INLINE_ lock_return_t acquire_mutex_lock_or_wait(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval = MUTEX_LOCK;

    tdx_debug_assert(lock_ptr != NULL);

    while (retval != MUTEX_FREE)
    {
        retval = _lock_cmpxchg_8bit(MUTEX_FREE, MUTEX_LOCK, lock_ptr);

        if (retval != MUTEX_FREE)
        {
            ia32_pause();
        }
    }

    return LOCK_RET_SUCCESS;
}
#endif // defined(DEBUGFEATURE_TDX_DBG_TRACE)

_STATIC_INLINE_ void release_mutex_lock(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval = _lock_cmpxchg_8bit(MUTEX_LOCK, MUTEX_FREE, lock_ptr);

    // Check that the previous lock was actually taken
    tdx_sanity_check((retval == MUTEX_LOCK), FATAL_ERROR_ID_188, 0);
}

//Sharex lock layout:  [ Readers count [14:1] |  Exclusive lock [0] ]
typedef enum
{
    SHAREX_FREE = 0, SHAREX_SINGLE_READER = BIT(1), SHAREX_EXCLUSIVE_LOCK = BIT(0)
} sharex_state_t;

//Host-priority sharex lock layout:  [ Readers count [14:2] | Host-priority flag [1] |  Exclusive lock [0] ]
typedef enum
{
    SHAREX_HP_FREE = 0,
    SHAREX_HP_EXCLUSIVE_LOCK = BIT(0),
    SHAREX_HP_HOST_PRIORITY = BIT(1),
    SHAREX_HP_SINGLE_READER = BIT(2)
} sharex_hp_state_t;


typedef union ALIGN(2)
{
    struct
    {
        uint16_t exclusive :1;
        uint16_t counter   :15;
    };
    uint16_t raw;
} sharex_lock_t;
tdx_static_assert(sizeof(sharex_lock_t) == 2, sharex_lock_t);

#define SHAREX_FULL_COUNTER            0x7FFF
#define SHAREX_FULL_COUNTER_NO_WRITER  0xFFFE

_STATIC_INLINE_ lock_return_t acquire_sharex_lock_sh(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_xadd_16b(&lock_ptr->raw, 2);

    // Check that we don't overflow the counter when only readers are on the lock
    tdx_sanity_check((retval.raw != SHAREX_FULL_COUNTER_NO_WRITER), FATAL_ERROR_ID_189, 1);

    return (retval.exclusive == 0) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t acquire_sharex_lock_ex(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_FREE, SHAREX_EXCLUSIVE_LOCK, &lock_ptr->raw);

    return (retval.raw == SHAREX_FREE) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t acquire_sharex_lock(sharex_lock_t * lock_ptr, lock_type_t lock_type)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        return acquire_sharex_lock_ex(lock_ptr);
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        return acquire_sharex_lock_sh(lock_ptr);
    }

    tdx_sanity_check(0, FATAL_ERROR_ID_190, 2);

    // Not supposed to return this after sanity check
    return LOCK_RET_FAIL;
}

_STATIC_INLINE_ void release_sharex_lock_sh(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_xadd_16b(&lock_ptr->raw, (uint16_t)-2);

    // Check that the previous lock wasn't exclusively taken, or wasn't taken at all
    tdx_sanity_check(!(retval.exclusive == 1 || retval.counter == 0), FATAL_ERROR_ID_191, 3);
}

_STATIC_INLINE_ void release_sharex_lock_ex(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _xchg_16b(&lock_ptr->raw, SHAREX_FREE);

    //Check if lock wasn't free, or shared
    tdx_sanity_check(retval.exclusive == 1, FATAL_ERROR_ID_192, 4);
}

_STATIC_INLINE_ void release_sharex_lock(sharex_lock_t * lock_ptr, lock_type_t lock_type)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        release_sharex_lock_ex(lock_ptr);
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        release_sharex_lock_sh(lock_ptr);
    }
    else
    {
        tdx_sanity_check(0, FATAL_ERROR_ID_193, 5);
    }
}

_STATIC_INLINE_ lock_return_t promote_sharex_lock(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_SINGLE_READER, SHAREX_EXCLUSIVE_LOCK, &lock_ptr->raw);

    //Check if lock was already exclusive or free
    tdx_sanity_check(!(retval.exclusive == 1 || retval.raw == SHAREX_FREE), FATAL_ERROR_ID_194, 6);

    return (retval.counter == 1) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t demote_sharex_lock(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _xchg_16b(&lock_ptr->raw, SHAREX_SINGLE_READER);

    //Check if lock wasn't free, or shared
    tdx_sanity_check(retval.exclusive == 1, FATAL_ERROR_ID_195, 7);

    return LOCK_RET_SUCCESS;
}

// SEPT locks:
_STATIC_INLINE_ api_error_type sept_lock_acquire_host(ia32e_sept_t* sept_ptr)
{
    bool_t ret_val = _lock_bts_64b(&sept_ptr->raw, SEPT_ENTRY_TDEL_BIT_POSITION) == 0;
    if (!ret_val)
    {
        // The lock is already taken. Just set (no need to check return value) the HP bit
        // and return BUSY_HOST PRIORITY error code
        (void)_lock_bts_64b(&sept_ptr->raw, SEPT_ENTRY_TDHP_BIT_POSITION);
        return TDX_OPERAND_BUSY;
    }

    // IF lock successfully acquired, reset the HP bit.
    (void)_lock_btr_64b(&sept_ptr->raw, SEPT_ENTRY_TDHP_BIT_POSITION);

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_type sept_lock_acquire_guest(ia32e_sept_t* sept_ptr)
{
    // Check the HP bit
    if(sept_ptr->hp)
    {
        return TDX_OPERAND_BUSY_HOST_PRIORITY;
    }

    bool_t ret_val = _lock_bts_64b(&sept_ptr->raw, SEPT_ENTRY_TDEL_BIT_POSITION) == 0;
    if (!ret_val)
    {
        return TDX_OPERAND_BUSY;
    }

    // Lock is successfully acquired.

    return TDX_SUCCESS;
}

_STATIC_INLINE_ void sept_lock_release(ia32e_sept_t* sept_ptr)
{
    tdx_sanity_check(sept_ptr->raw & BIT(SEPT_ENTRY_TDEL_BIT_POSITION) , FATAL_ERROR_ID_196, 8);

    // Lock is taken. Just release it by resetting the TDEL bit
    (void)_lock_btr_64b(&sept_ptr->raw, SEPT_ENTRY_TDEL_BIT_POSITION);
}

_STATIC_INLINE_ void sept_lock_release_local(ia32e_sept_t* sept_ptr)
{
    // set the TDEL bit to 0 on a local SEPT entry copy. No need for atomic operations
    sept_ptr->raw &= (uint64_t)~(BIT(SEPT_ENTRY_TDEL_BIT_POSITION));
}



///////////////////////////////////////////////////////////////////////////////
/// Sharex host-priority lock implementation:
///////////////////////////////////////////////////////////////////////////////

typedef union ALIGN(2)
{
    struct
    {
        uint16_t exclusive :1;
        uint16_t host_prio :1;
        uint16_t counter   :14;
    };
    uint16_t raw;
} sharex_hp_lock_t;
tdx_static_assert(sizeof(sharex_hp_lock_t) == 2, sharex_hp_lock_t);

_STATIC_INLINE_ bool_t is_lock_hp_set(sharex_hp_lock_t* lock)
{
    return lock->host_prio;
}

#define SHAREX_HP_FULL_COUNTER           0x3FFF
#define HOST_PRIORITY_MASK               0x0002

_STATIC_INLINE_ api_error_code_e acquire_sharex_lock_hp_sh(sharex_hp_lock_t * lock_ptr, bool_t is_guest)
{
    sharex_hp_lock_t retval = { .raw = 0 };

    tdx_debug_assert(lock_ptr != NULL);

    if (is_guest)
    {
        // Check th HP bit
        if((lock_ptr->raw & HOST_PRIORITY_MASK) != 0)
        {
            return TDX_OPERAND_BUSY_HOST_PRIORITY;
        }

        // Increment SHARE_COUNTER
        retval.raw = _lock_xadd_16b(&lock_ptr->raw, SHAREX_HP_SINGLE_READER);

        if (retval.exclusive)
        {
            return TDX_OPERAND_BUSY; // Counter is n/a
        }

        // Sanity-check the counter after we know that exclusive bit was not set
        // Only when exclusive bit is not set the shared-counters has "real" "readers"
        // And that number should not overflow
        tdx_sanity_check((retval.counter != SHAREX_HP_FULL_COUNTER), FATAL_ERROR_ID_197, 10);
    }
    else
    {
        // Increment SHARE_COUNTER
        retval.raw = _lock_xadd_16b(&lock_ptr->raw, SHAREX_HP_SINGLE_READER);

        if (retval.exclusive)
        {
            _lock_or_16b(&lock_ptr->raw, SHAREX_HP_HOST_PRIORITY);
            return TDX_OPERAND_BUSY;
        }
        else if (retval.host_prio)
        {
            // Leave SHARE_COUNTER incremented and reset HP bit
            _lock_and_16b(&lock_ptr->raw, (uint16_t)~SHAREX_HP_HOST_PRIORITY);
        }

        // Sanity-check the counter after we know that exclusive bit was not set
        // Only when exclusive bit is not set the shared-counters has "real" "readers"
        // And that number should not overflow
        tdx_sanity_check((retval.counter != SHAREX_HP_FULL_COUNTER), FATAL_ERROR_ID_198, 11);
    }

    return TDX_SUCCESS;
}

_STATIC_INLINE_ api_error_code_e acquire_sharex_lock_hp_ex(sharex_hp_lock_t * lock_ptr, bool_t is_guest)
{
    sharex_hp_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_HP_FREE, SHAREX_HP_EXCLUSIVE_LOCK, &lock_ptr->raw); // Set EXCLUSIVE to 1

    if (retval.raw == SHAREX_HP_FREE)
    {
        return TDX_SUCCESS;
    }
    else if (retval.raw == SHAREX_HP_HOST_PRIORITY)
    {
        if (is_guest)
        {
            return TDX_OPERAND_BUSY_HOST_PRIORITY;
        }
        else
        {
            // HOST_PRIORITY is 1, try again if you are host
            // Set EXCLUSIVE to 1, clear HOST_PRIORITY
            retval.raw = _lock_cmpxchg_16b(SHAREX_HP_HOST_PRIORITY, SHAREX_HP_EXCLUSIVE_LOCK, &lock_ptr->raw);
            return (retval.raw == SHAREX_HP_HOST_PRIORITY) ? TDX_SUCCESS : TDX_OPERAND_BUSY;
        }
    }
    else
    {
        if (is_guest)
        {
            return TDX_OPERAND_BUSY;
        }
        else
        {
            _lock_or_16b(&lock_ptr->raw, SHAREX_HP_HOST_PRIORITY);
            return TDX_OPERAND_BUSY;
        }
    }
}

// shared/exclusive lock with host priority
_STATIC_INLINE_ api_error_code_e acquire_sharex_lock_hp(sharex_hp_lock_t * lock_ptr, lock_type_t lock_type,
                                                        bool_t is_guest)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        return acquire_sharex_lock_hp_ex(lock_ptr, is_guest);
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        return acquire_sharex_lock_hp_sh(lock_ptr, is_guest);
    }

    tdx_sanity_check(0, FATAL_ERROR_ID_199, 12);

    // Not supposed to return this after sanity check
    return UNINITIALIZE_ERROR;
}

_STATIC_INLINE_ void release_sharex_lock_hp_sh(sharex_hp_lock_t * lock_ptr)
{
    sharex_hp_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_xadd_16b(&lock_ptr->raw, (uint16_t)-SHAREX_HP_SINGLE_READER);

    // Check that the previous lock wasn't exclusively taken, or wasn't taken at all
    tdx_sanity_check(!(retval.exclusive == 1 || retval.counter == 0), FATAL_ERROR_ID_200, 13);
}

_STATIC_INLINE_ void release_sharex_lock_hp_ex(sharex_hp_lock_t * lock_ptr)
{
    tdx_debug_assert(lock_ptr != NULL);

    //Check if lock isn't free, or shared
    tdx_sanity_check(lock_ptr->exclusive == 1, FATAL_ERROR_ID_201, 14);

    _lock_and_16b(&lock_ptr->raw, SHAREX_HP_HOST_PRIORITY); // save HP state and reset counter and exclusive bit
}

_STATIC_INLINE_ void release_sharex_lock_hp(sharex_hp_lock_t * lock_ptr, lock_type_t lock_type)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        release_sharex_lock_hp_ex(lock_ptr);
        return;
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        release_sharex_lock_hp_sh(lock_ptr);
        return;
    }

    tdx_sanity_check(0, FATAL_ERROR_ID_202, 15);
}

_STATIC_INLINE_ api_error_code_e promote_sharex_lock_hp(sharex_hp_lock_t * lock_ptr)
{
    sharex_hp_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_HP_SINGLE_READER, SHAREX_HP_EXCLUSIVE_LOCK, &lock_ptr->raw);

    //Check if lock was already exclusive or free
    tdx_sanity_check(!(retval.exclusive == 1 || retval.raw == SHAREX_HP_FREE), FATAL_ERROR_ID_203, 16);

    if (retval.raw == SHAREX_HP_SINGLE_READER)
    {
        return TDX_SUCCESS;
    }
    else if (retval.raw == (SHAREX_HP_SINGLE_READER | SHAREX_HP_HOST_PRIORITY))
    {
        retval.raw = _lock_cmpxchg_16b((SHAREX_HP_SINGLE_READER | SHAREX_HP_HOST_PRIORITY),
                                        SHAREX_HP_EXCLUSIVE_LOCK, &lock_ptr->raw);

        //Check again if lock was already exclusive or free
        tdx_sanity_check(!(retval.exclusive == 1 || retval.raw == SHAREX_HP_FREE), FATAL_ERROR_ID_204, 17);

        if (retval.raw == (SHAREX_HP_SINGLE_READER | SHAREX_HP_HOST_PRIORITY))
        {
            return TDX_SUCCESS;
        }
        else
        {
            return TDX_OPERAND_BUSY;
        }
    }
    else
    {
        _lock_or_16b(&lock_ptr->raw, SHAREX_HP_HOST_PRIORITY);
        return TDX_OPERAND_BUSY;
    }
}


_STATIC_INLINE_ void release_bit_lock(uint32_t* mem_ptr, uint32_t bit_idx)
{
    tdx_debug_assert(mem_ptr != NULL);

    bool_t retval;
    retval = _lock_btr_32b(mem_ptr, bit_idx);

    tdx_sanity_check(retval != 0, FATAL_ERROR_ID_205, 18);
}

#endif /* SRC_COMMON_HELPERS_TDX_LOCKS_H_ */
