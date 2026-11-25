#ifndef _LINUX_STRING_H
#define _LINUX_STRING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void *dosdrm_memcpy(void *dst, const void *src, size_t n);
void *dosdrm_memmove(void *dst, const void *src, size_t n);
void *dosdrm_memset(void *dst, int c, size_t n);
int dosdrm_memcmp(const void *a, const void *b, size_t n);
size_t dosdrm_strlen(const char *s);
size_t dosdrm_strnlen(const char *s, size_t max_len);
int dosdrm_strcmp(const char *a, const char *b);
int dosdrm_strncmp(const char *a, const char *b, size_t n);

#if !defined(__DOSDRM_HOST_TEST__)
#define memcpy  dosdrm_memcpy
#define memmove dosdrm_memmove
#define memset  dosdrm_memset
#define memcmp  dosdrm_memcmp
#define strlen  dosdrm_strlen
#define strnlen dosdrm_strnlen
#define strcmp  dosdrm_strcmp
#define strncmp dosdrm_strncmp
#else
#include <string.h>
#endif

#ifdef __cplusplus
}
#endif

#endif
