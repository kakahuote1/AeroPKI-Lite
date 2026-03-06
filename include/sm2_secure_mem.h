/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file sm2_secure_mem.h
 * @brief Secure memory cleansing helpers.
 */

#ifndef SM2_SECURE_MEM_H
#define SM2_SECURE_MEM_H

#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#ifdef __cplusplus
extern "C"
{
#endif

    static inline void sm2_secure_memzero(void *ptr, size_t len)
    {
        if (!ptr || len == 0)
            return;

#if OPENSSL_VERSION_NUMBER >= 0x00907000L
        OPENSSL_cleanse(ptr, len);
#else
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len-- > 0)
        *p++ = 0;
#endif
    }

#ifdef __cplusplus
}
#endif

#endif /* SM2_SECURE_MEM_H */
