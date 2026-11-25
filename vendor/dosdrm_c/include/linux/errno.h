#ifndef _LINUX_ERRNO_H
#define _LINUX_ERRNO_H

#ifndef EPERM
#define EPERM        1
#endif
#ifndef ENOENT
#define ENOENT       2
#endif
#ifndef EIO
#define EIO          5
#endif
#ifndef ENXIO
#define ENXIO        6
#endif
#ifndef EAGAIN
#define EAGAIN      11
#endif
#ifndef ENOMEM
#define ENOMEM      12
#endif
#ifndef EACCES
#define EACCES      13
#endif
#ifndef EFAULT
#define EFAULT      14
#endif
#ifndef EBUSY
#define EBUSY       16
#endif
#ifndef EEXIST
#define EEXIST      17
#endif
#ifndef ENODEV
#define ENODEV      19
#endif
#ifndef EINVAL
#define EINVAL      22
#endif
#ifndef ENOSPC
#define ENOSPC      28
#endif
#ifndef ERANGE
#define ERANGE      34
#endif
#ifndef ENOSYS
#define ENOSYS      38
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP  95
#endif
#ifndef ENOTSUP
#define ENOTSUP     EOPNOTSUPP
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT  110
#endif

#endif
