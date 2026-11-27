/*
 * Minimal freestanding x86-64 ELF64 dynamic linker (`ld-linux-x86-64.so.2`) for D-CMPL L3.
 *
 * Runs completely unmodified inside the Linux FORWARD child process via PT_INTERP:
 * - self-relocates using AT_BASE + _DYNAMIC;
 * - reads the main executable's PT_LOAD / PT_DYNAMIC / PT_TLS / PT_GNU_RELRO from AT_PHDR;
 * - opens and maps DT_NEEDED shared libraries (.so) from /lib64, /lib, /usr/lib via openat + mmap
 *   (PROT_NONE reservation + MAP_FIXED RX/RW segments + .bss zeroing);
 * - resolves R_X86_64_RELATIVE, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64, and
 *   R_X86_64_TPOFF64 across all loaded objects;
 * - enforces PT_GNU_RELRO via mprotect(..., PROT_READ);
 * - allocates and installs PT_TLS via arch_prctl(ARCH_SET_FS);
 * - runs DT_INIT_ARRAY constructors and transfers control to AT_ENTRY with the original stack.
 */

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;
typedef unsigned short u16;
typedef unsigned char u8;

static i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    i64 r;
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return r;
}

enum {
    SYS_read = 0, SYS_write = 1, SYS_close = 3, SYS_mmap = 9, SYS_mprotect = 10,
    SYS_arch_prctl = 158, SYS_exit_group = 231, SYS_openat = 257,
};
enum { AT_FDCWD = -100, O_RDONLY = 0, ARCH_SET_FS = 0x1002 };
enum { PROT_NONE = 0, PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4 };
enum { MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANONYMOUS = 0x20 };
enum { AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5, AT_BASE = 7, AT_ENTRY = 9 };
enum { PT_LOAD = 1, PT_DYNAMIC = 2, PT_PHDR = 6, PT_TLS = 7, PT_GNU_RELRO = 0x6474e552 };
enum { PF_X = 1, PF_W = 2, PF_R = 4 };
enum {
    DT_NULL = 0, DT_NEEDED = 1, DT_PLTRELSZ = 2, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6,
    DT_RELA = 7, DT_RELASZ = 8, DT_JMPREL = 23, DT_INIT_ARRAY = 25, DT_INIT_ARRAYSZ = 27,
    DT_GNU_HASH = 0x6ffffef5,
};
enum {
    R_X86_64_NONE = 0, R_X86_64_64 = 1, R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7,
    R_X86_64_RELATIVE = 8, R_X86_64_TPOFF64 = 18,
};

typedef struct { u8 e_ident[16]; u16 e_type, e_machine; u32 e_version; u64 e_entry, e_phoff, e_shoff; u32 e_flags; u16 e_ehsize, e_phentsize, e_phnum; } Elf64_Ehdr;
typedef struct { u32 p_type, p_flags; u64 p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align; } Elf64_Phdr;
typedef struct { i64 d_tag; u64 d_val; } Elf64_Dyn;
typedef struct { u32 st_name; u8 st_info, st_other; u16 st_shndx; u64 st_value, st_size; } Elf64_Sym;
typedef struct { u64 r_offset, r_info; i64 r_addend; } Elf64_Rela;

static void die(const char *msg, int code)
{
    u64 n = 0;
    while (msg[n])
        n++;
    sys6(SYS_write, 2, (i64)msg, (i64)n, 0, 0, 0);
    for (;;)
        sys6(SYS_exit_group, code, 0, 0, 0, 0, 0);
}

static int streq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static void memzero(void *p, u64 n)
{
    u8 *b = (u8 *)p;
    for (u64 i = 0; i < n; i++)
        b[i] = 0;
}

static void memcopy(void *dst, const void *src, u64 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u64 i = 0; i < n; i++)
        d[i] = s[i];
}

typedef struct {
    u64 bias;
    const Elf64_Dyn *dyn;
    const char *strtab;
    const Elf64_Sym *symtab;
    u32 nsyms;
    const Elf64_Rela *rela;
    u64 relasz;
    const Elf64_Rela *jmprel;
    u64 pltrelsz;
    u64 init_array;
    u64 init_arraysz;
    u64 relro_vaddr;
    u64 relro_memsz;
    u64 tls_vaddr;
    u64 tls_filesz;
    u64 tls_memsz;
    u64 tls_align;
    i64 tls_tpoff;
} Mod;

static u32 gnu_hash_nsyms(const u32 *gh)
{
    u32 nbuckets = gh[0];
    u32 symoffset = gh[1];
    u32 bloom_size = gh[2];
    const u64 *bloom = (const u64 *)(gh + 4);
    const u32 *buckets = (const u32 *)(bloom + bloom_size);
    const u32 *chains = buckets + nbuckets;
    u32 max_idx = symoffset;
    for (u32 i = 0; i < nbuckets; i++) {
        if (buckets[i] >= max_idx)
            max_idx = buckets[i];
    }
    if (max_idx < symoffset)
        return symoffset;
    while ((chains[max_idx - symoffset] & 1) == 0)
        max_idx++;
    return max_idx + 1;
}

static void parse_dyn(Mod *m)
{
    if (!m->dyn)
        return;
    const u32 *hash = 0;
    const u32 *gnuhash = 0;
    for (const Elf64_Dyn *d = m->dyn; d->d_tag != DT_NULL; d++) {
        u64 v = d->d_val;
        switch (d->d_tag) {
        case DT_STRTAB:      m->strtab = (const char *)(v < m->bias ? m->bias + v : v); break;
        case DT_SYMTAB:      m->symtab = (const Elf64_Sym *)(v < m->bias ? m->bias + v : v); break;
        case DT_RELA:        m->rela = (const Elf64_Rela *)(v < m->bias ? m->bias + v : v); break;
        case DT_RELASZ:      m->relasz = v; break;
        case DT_JMPREL:      m->jmprel = (const Elf64_Rela *)(v < m->bias ? m->bias + v : v); break;
        case DT_PLTRELSZ:    m->pltrelsz = v; break;
        case DT_INIT_ARRAY:  m->init_array = (v < m->bias ? m->bias + v : v); break;
        case DT_INIT_ARRAYSZ: m->init_arraysz = v; break;
        case DT_HASH:        hash = (const u32 *)(v < m->bias ? m->bias + v : v); break;
        case DT_GNU_HASH:    gnuhash = (const u32 *)(v < m->bias ? m->bias + v : v); break;
        default: break;
        }
    }
    if (hash)
        m->nsyms = hash[1];
    else if (gnuhash)
        m->nsyms = gnu_hash_nsyms(gnuhash);
}

static u64 lookup_sym(Mod *mods, int nmods, const char *name)
{
    for (int i = 0; i < nmods; i++) {
        Mod *m = &mods[i];
        if (!m->symtab || !m->strtab)
            continue;
        for (u32 k = 1; k < m->nsyms; k++) {
            const Elf64_Sym *s = &m->symtab[k];
            if (s->st_shndx == 0)
                continue;
            if (streq(m->strtab + s->st_name, name))
                return m->bias + s->st_value;
        }
    }
    return 0;
}

static void apply_relas(Mod *mods, int nmods, Mod *m, const Elf64_Rela *rs, u64 sz)
{
    if (!rs || sz == 0)
        return;
    u64 n = sz / sizeof(Elf64_Rela);
    for (u64 i = 0; i < n; i++) {
        const Elf64_Rela *r = &rs[i];
        u32 ty = (u32)(r->r_info & 0xffffffffu);
        u32 sym_i = (u32)(r->r_info >> 32);
        u64 *where = (u64 *)(m->bias + r->r_offset);
        if (ty == R_X86_64_NONE)
            continue;
        if (ty == R_X86_64_RELATIVE) {
            *where = m->bias + (u64)r->r_addend;
            continue;
        }
        if (ty == R_X86_64_TPOFF64) {
            u64 val = (sym_i && m->symtab) ? m->symtab[sym_i].st_value : 0;
            *where = (u64)(m->tls_tpoff + (i64)val + r->r_addend);
            continue;
        }
        if (ty == R_X86_64_GLOB_DAT || ty == R_X86_64_JUMP_SLOT || ty == R_X86_64_64) {
            const char *sname = m->strtab + m->symtab[sym_i].st_name;
            u64 target = lookup_sym(mods, nmods, sname);
            if (!target && (m->symtab[sym_i].st_info >> 4) != 2) /* not STB_WEAK */
                die("ld-linux: unresolved symbol\n", 127);
            *where = target + (ty == R_X86_64_64 ? (u64)r->r_addend : 0);
        }
    }
}

static int open_so(const char *name)
{
    static const char *const dirs[] = { "/lib64/", "/lib/", "/usr/lib/" };
    char path[256];
    for (int d = 0; d < 3; d++) {
        u64 pos = 0;
        for (const char *p = dirs[d]; *p && pos < 200; p++)
            path[pos++] = *p;
        for (const char *p = name; *p && pos < 254; p++)
            path[pos++] = *p;
        path[pos] = 0;
        i64 fd = sys6(SYS_openat, AT_FDCWD, (i64)path, O_RDONLY, 0, 0, 0);
        if (fd >= 0)
            return (int)fd;
    }
    return -1;
}

static void load_so(Mod *out, const char *name)
{
    int fd = open_so(name);
    if (fd < 0)
        die("ld-linux: shared library not found\n", 127);
    u8 hdr[4096];
    i64 got = sys6(SYS_read, fd, (i64)hdr, sizeof(hdr), 0, 0, 0);
    if (got < (i64)sizeof(Elf64_Ehdr))
        die("ld-linux: short .so header\n", 127);
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)hdr;
    if (eh->e_phoff + (u64)eh->e_phnum * sizeof(Elf64_Phdr) > (u64)got)
        die("ld-linux: .so phdrs exceed 4 KiB\n", 127);
    const Elf64_Phdr *ph = (const Elf64_Phdr *)(hdr + eh->e_phoff);
    u64 lo = (u64)-1, hi = 0;
    for (u16 i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_memsz > 0) {
            u64 s = ph[i].p_vaddr & ~4095ul;
            u64 e = (ph[i].p_vaddr + ph[i].p_memsz + 4095ul) & ~4095ul;
            if (s < lo) lo = s;
            if (e > hi) hi = e;
        }
    }
    u64 span = hi - lo;
    i64 base_r = sys6(SYS_mmap, 0, (i64)span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base_r < 0 && base_r > -4096)
        die("ld-linux: cannot reserve .so span\n", 127);
    u64 bias = (u64)base_r - lo;
    memzero(out, sizeof(*out));
    out->bias = bias;
    for (u16 i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD && ph[i].p_memsz > 0) {
            u64 ps = ph[i].p_vaddr & ~4095ul;
            u64 pe = (ph[i].p_vaddr + ph[i].p_memsz + 4095ul) & ~4095ul;
            u64 off = ph[i].p_offset & ~4095ul;
            u64 prot = PROT_READ;
            if (ph[i].p_flags & PF_W) prot |= PROT_WRITE;
            if (ph[i].p_flags & PF_X) prot |= PROT_EXEC;
            i64 mr = sys6(SYS_mmap, (i64)(bias + ps), (i64)(pe - ps), (i64)prot, MAP_PRIVATE | MAP_FIXED, fd, (i64)off);
            if (mr < 0 && mr > -4096)
                die("ld-linux: cannot map .so segment\n", 127);
            if ((ph[i].p_flags & PF_W) && ph[i].p_memsz > ph[i].p_filesz)
                memzero((void *)(bias + ph[i].p_vaddr + ph[i].p_filesz), ph[i].p_memsz - ph[i].p_filesz);
        } else if (ph[i].p_type == PT_DYNAMIC) {
            out->dyn = (const Elf64_Dyn *)(bias + ph[i].p_vaddr);
        } else if (ph[i].p_type == PT_GNU_RELRO) {
            out->relro_vaddr = ph[i].p_vaddr;
            out->relro_memsz = ph[i].p_memsz;
        }
    }
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    parse_dyn(out);
}

extern Elf64_Dyn _DYNAMIC[];

__attribute__((used)) u64 ld_main(u64 *sp)
{
    u64 argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    while (*envp)
        envp++;
    u64 *auxv = (u64 *)(envp + 1);
    u64 phdr_va = 0, phnum = 0, ld_base = 0, exe_entry = 0;
    for (u64 *a = auxv; a[0] != AT_NULL; a += 2) {
        if (a[0] == AT_PHDR) phdr_va = a[1];
        else if (a[0] == AT_PHNUM) phnum = a[1];
        else if (a[0] == AT_BASE) ld_base = a[1];
        else if (a[0] == AT_ENTRY) exe_entry = a[1];
    }

    /* Self-relocate ld-linux-x86-64.so.2 (R_X86_64_RELATIVE). */
    const Elf64_Rela *self_rela = 0;
    u64 self_relasz = 0;
    for (const Elf64_Dyn *d = _DYNAMIC; d->d_tag != DT_NULL; d++) {
        if (d->d_tag == DT_RELA) self_rela = (const Elf64_Rela *)(ld_base + d->d_val);
        else if (d->d_tag == DT_RELASZ) self_relasz = d->d_val;
    }
    if (self_rela) {
        for (u64 i = 0; i < self_relasz / sizeof(Elf64_Rela); i++) {
            if ((self_rela[i].r_info & 0xffffffffu) == R_X86_64_RELATIVE)
                *(u64 *)(ld_base + self_rela[i].r_offset) = ld_base + (u64)self_rela[i].r_addend;
        }
    }

    if (!phdr_va || !phnum || !exe_entry)
        die("ld-linux: missing auxv\n", 127);

    Mod mods[8];
    memzero(mods, sizeof(mods));
    int nmods = 1;
    const Elf64_Phdr *ph = (const Elf64_Phdr *)phdr_va;
    u64 exe_bias = 0;
    for (u64 i = 0; i < phnum; i++) {
        if (ph[i].p_type == PT_PHDR) {
            exe_bias = phdr_va - ph[i].p_vaddr;
            break;
        }
    }
    mods[0].bias = exe_bias;
    for (u64 i = 0; i < phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC)
            mods[0].dyn = (const Elf64_Dyn *)(exe_bias + ph[i].p_vaddr);
        else if (ph[i].p_type == PT_GNU_RELRO) {
            mods[0].relro_vaddr = ph[i].p_vaddr;
            mods[0].relro_memsz = ph[i].p_memsz;
        } else if (ph[i].p_type == PT_TLS) {
            mods[0].tls_vaddr = ph[i].p_vaddr;
            mods[0].tls_filesz = ph[i].p_filesz;
            mods[0].tls_memsz = ph[i].p_memsz;
            mods[0].tls_align = ph[i].p_align ? ph[i].p_align : 1;
        }
    }
    parse_dyn(&mods[0]);

    /* Load DT_NEEDED shared libraries. */
    if (mods[0].dyn && mods[0].strtab) {
        for (const Elf64_Dyn *d = mods[0].dyn; d->d_tag != DT_NULL && nmods < 8; d++) {
            if (d->d_tag == DT_NEEDED)
                load_so(&mods[nmods++], mods[0].strtab + d->d_val);
        }
    }

    /* Setup static PT_TLS block (x86-64 Variant II: TLS sits directly below %fs:0 TCB, sized
     * by align_up(p_memsz, p_align) matching the linker's negative TPOFF layout). */
    u64 align = mods[0].tls_align ? mods[0].tls_align : 1;
    u64 tls_sz = (mods[0].tls_memsz + align - 1ul) & ~(align - 1ul);
    i64 tls_mem = sys6(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tls_mem < 0 && tls_mem > -4096)
        die("ld-linux: cannot allocate TLS\n", 127);
    u64 tcb_addr = (u64)tls_mem + 2048;
    *(u64 *)tcb_addr = tcb_addr; /* %fs:0 -> self */
    if (mods[0].tls_memsz > 0) {
        mods[0].tls_tpoff = -(i64)tls_sz;
        u64 dst = tcb_addr - tls_sz;
        if (mods[0].tls_filesz > 0)
            memcopy((void *)dst, (const void *)(mods[0].bias + mods[0].tls_vaddr), mods[0].tls_filesz);
    }
    sys6(SYS_arch_prctl, ARCH_SET_FS, (i64)tcb_addr, 0, 0, 0, 0);

    /* Apply relocations in all modules, then enforce PT_GNU_RELRO via mprotect(PROT_READ). */
    for (int i = nmods - 1; i >= 0; i--) {
        apply_relas(mods, nmods, &mods[i], mods[i].rela, mods[i].relasz);
        apply_relas(mods, nmods, &mods[i], mods[i].jmprel, mods[i].pltrelsz);
        if (mods[i].relro_memsz > 0) {
            u64 rlo = (mods[i].bias + mods[i].relro_vaddr) & ~4095ul;
            u64 rhi = (mods[i].bias + mods[i].relro_vaddr + mods[i].relro_memsz) & ~4095ul;
            if (rhi > rlo)
                sys6(SYS_mprotect, (i64)rlo, (i64)(rhi - rlo), PROT_READ, 0, 0, 0);
        }
    }

    /* Run DT_INIT_ARRAY constructors (shared libraries first, then main executable). */
    for (int i = nmods - 1; i >= 0; i--) {
        if (mods[i].init_array && mods[i].init_arraysz) {
            typedef void (*init_fn)(void);
            init_fn *arr = (init_fn *)mods[i].init_array;
            u64 cnt = mods[i].init_arraysz / sizeof(init_fn);
            for (u64 k = 0; k < cnt; k++) {
                if (arr[k])
                    arr[k]();
            }
        }
    }

    return exe_entry;
}

void _start(void);
__asm__(".globl _start\n"
        "_start:\n"
        "  mov %rsp, %r12\n"
        "  mov %rsp, %rdi\n"
        "  and $-16, %rsp\n"
        "  call ld_main\n"
        "  mov %r12, %rsp\n"
        "  xor %rdx, %rdx\n"
        "  jmp *%rax\n");
