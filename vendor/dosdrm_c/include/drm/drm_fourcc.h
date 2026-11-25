#ifndef _DRM_FOURCC_H
#define _DRM_FOURCC_H

#include <linux/types.h>

#define fourcc_code(a, b, c, d) \
    ((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))

#define DRM_FORMAT_XRGB8888     fourcc_code('X', 'R', '2', '4')
#define DRM_FORMAT_ARGB8888     fourcc_code('A', 'R', '2', '4')
#define DRM_FORMAT_XBGR8888     fourcc_code('X', 'B', '2', '4')
#define DRM_FORMAT_ABGR8888     fourcc_code('A', 'B', '2', '4')
#define DRM_FORMAT_XRGB2101010  fourcc_code('X', 'R', '3', '0')
#define DRM_FORMAT_ARGB2101010  fourcc_code('A', 'R', '3', '0')

#define DRM_FORMAT_MOD_LINEAR   0ULL
#define DRM_FORMAT_MOD_INVALID  0x00ffffffffffffffULL

#endif
