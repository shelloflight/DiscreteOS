#ifndef _DRM_MODE_H
#define _DRM_MODE_H

#include <linux/types.h>

#define DRM_MODE_TYPE_PREFERRED (1u << 3)
#define DRM_MODE_TYPE_DRIVER    (1u << 6)

#define DRM_MODE_FLAG_PHSYNC    (1u << 0)
#define DRM_MODE_FLAG_NHSYNC    (1u << 1)
#define DRM_MODE_FLAG_PVSYNC    (1u << 2)
#define DRM_MODE_FLAG_NVSYNC    (1u << 3)

#define DRM_MODE_ATOMIC_TEST_ONLY       0x0100u
#define DRM_MODE_ATOMIC_NONBLOCK        0x0200u
#define DRM_MODE_ATOMIC_ALLOW_MODESET   0x0400u
#define DRM_MODE_PAGE_FLIP_EVENT        0x0001u
#define DRM_MODE_PAGE_FLIP_ASYNC        0x0002u

struct drm_mode_modeinfo {
    __u32 clock;
    __u16 hdisplay;
    __u16 hsync_start;
    __u16 hsync_end;
    __u16 htotal;
    __u16 hskew;
    __u16 vdisplay;
    __u16 vsync_start;
    __u16 vsync_end;
    __u16 vtotal;
    __u16 vscan;
    __u32 vrefresh;
    __u32 flags;
    __u32 type;
    char name[32];
};

#endif
