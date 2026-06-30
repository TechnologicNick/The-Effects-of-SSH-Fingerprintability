#ifndef OPENSSH_UMAC_XMALLOC_H
#define OPENSSH_UMAC_XMALLOC_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static inline void *
xmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL) {
        abort();
    }
    return ptr;
}

static inline void *
xcalloc(size_t n, size_t size)
{
    void *ptr = calloc(n, size);
    if (ptr == NULL) {
        abort();
    }
    return ptr;
}

static inline void
freezero(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }
    memset(ptr, 0, size);
    free(ptr);
}

#endif
