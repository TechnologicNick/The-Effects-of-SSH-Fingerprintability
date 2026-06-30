#ifndef OPENSSH_UMAC_MISC_H
#define OPENSSH_UMAC_MISC_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__GLIBC__) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
static inline void
explicit_bzero(void *ptr, size_t size)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size-- > 0) {
        *p++ = 0;
    }
}
#endif

static inline uint32_t
get_u32(const void *ptr)
{
    const unsigned char *p = (const unsigned char *)ptr;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t
get_u32_le(const void *ptr)
{
    const unsigned char *p = (const unsigned char *)ptr;
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static inline void
put_u32(void *ptr, uint32_t value)
{
    unsigned char *p = (unsigned char *)ptr;
    p[0] = (unsigned char)((value >> 24) & 0xff);
    p[1] = (unsigned char)((value >> 16) & 0xff);
    p[2] = (unsigned char)((value >> 8) & 0xff);
    p[3] = (unsigned char)(value & 0xff);
}

#endif
