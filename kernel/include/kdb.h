/* kdb: kernel inspection commands on the boot console (kernel/kdb.c). */
#ifndef DOS_KDB_H
#define DOS_KDB_H

#include <stdbool.h>

bool kdb_command(const char *line);   /* false: not a kdb command */

#endif
