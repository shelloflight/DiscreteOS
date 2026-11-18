/*
 * The parts of the UEFI specification (2.10) the D-OS loader uses. Only what is called is typed;
 * unused table slots are plain pointers so the layouts stay exact. Calling convention: the
 * loader is built for x86_64-windows, whose default ABI is the UEFI (Microsoft x64) one.
 */
#ifndef DOS_EFI_H
#define DOS_EFI_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t efi_status;
typedef void    *efi_handle;
typedef uint16_t char16;

#define EFI_SUCCESS          0ull
#define EFI_ERR(n)           (0x8000000000000000ull | (n))
#define EFI_LOAD_ERROR       EFI_ERR(1)
#define EFI_INVALID_PARAMETER EFI_ERR(2)
#define EFI_UNSUPPORTED      EFI_ERR(3)
#define EFI_BUFFER_TOO_SMALL EFI_ERR(5)
#define EFI_NOT_FOUND        EFI_ERR(14)
#define EFI_SECURITY_VIOLATION EFI_ERR(26)

typedef struct { uint32_t a; uint16_t b, c; uint8_t d[8]; } efi_guid;

typedef struct {
    uint64_t signature;
    uint32_t revision, header_size, crc32, reserved;
} efi_table_header;

typedef struct efi_text_output {
    void *reset;
    efi_status (*output_string)(struct efi_text_output *self, const char16 *s);
    void *test_string, *query_mode, *set_mode, *set_attribute, *clear_screen, *set_cursor, *enable_cursor, *mode;
} efi_text_output;

typedef struct efi_text_input {
    void *reset;
    efi_status (*read_key)(struct efi_text_input *self, void *key);
    void *wait_for_key;
} efi_text_input;

enum efi_allocate_type { ALLOCATE_ANY = 0, ALLOCATE_MAX_ADDRESS = 1, ALLOCATE_ADDRESS = 2 };

enum efi_memory_type {
    EFI_RESERVED = 0, EFI_LOADER_CODE, EFI_LOADER_DATA, EFI_BS_CODE, EFI_BS_DATA, EFI_RT_CODE,
    EFI_RT_DATA, EFI_CONVENTIONAL, EFI_UNUSABLE, EFI_ACPI_RECLAIM, EFI_ACPI_NVS, EFI_MMIO,
    EFI_MMIO_PORT, EFI_PAL_CODE, EFI_PERSISTENT, EFI_UNACCEPTED,
};

typedef struct {
    uint32_t type;
    uint32_t pad;
    uint64_t phys_start;
    uint64_t virt_start;
    uint64_t pages;
    uint64_t attribute;
} efi_memory_descriptor;

typedef struct {
    efi_table_header hdr;
    void *raise_tpl, *restore_tpl;
    efi_status (*allocate_pages)(uint32_t type, uint32_t memory_type, uint64_t pages, uint64_t *addr);
    efi_status (*free_pages)(uint64_t addr, uint64_t pages);
    efi_status (*get_memory_map)(uint64_t *size, efi_memory_descriptor *map, uint64_t *key, uint64_t *desc_size, uint32_t *desc_version);
    efi_status (*allocate_pool)(uint32_t memory_type, uint64_t size, void **out);
    efi_status (*free_pool)(void *p);
    void *create_event, *set_timer, *wait_for_event, *signal_event, *close_event, *check_event;
    void *install_protocol, *reinstall_protocol, *uninstall_protocol;
    efi_status (*handle_protocol)(efi_handle h, const efi_guid *proto, void **out);
    void *reserved, *register_protocol_notify, *locate_handle, *locate_device_path, *install_configuration_table;
    void *load_image, *start_image, *exit, *unload_image;
    efi_status (*exit_boot_services)(efi_handle image, uint64_t map_key);
    void *get_next_monotonic_count;
    efi_status (*stall)(uint64_t microseconds);
    efi_status (*set_watchdog_timer)(uint64_t timeout, uint64_t code, uint64_t size, const char16 *data);
    void *connect_controller, *disconnect_controller;
    void *open_protocol, *close_protocol, *open_protocol_information;
    void *protocols_per_handle, *locate_handle_buffer;
    efi_status (*locate_protocol)(const efi_guid *proto, void *registration, void **out);
    void *install_multiple, *uninstall_multiple;
    void *calculate_crc32, *copy_mem, *set_mem, *create_event_ex;
} efi_boot_services;

typedef struct {
    efi_guid guid;
    void *table;
} efi_configuration_table;

/* EFI_TIME and the start of EFI_RUNTIME_SERVICES (only GetTime is used, before ExitBootServices). */
typedef struct {
    uint16_t year;          /* 1900 - 9999 */
    uint8_t  month, day, hour, minute, second, pad1;
    uint32_t nanosecond;
    int16_t  time_zone;     /* minutes from UTC, or 2047: unspecified (local time) */
    uint8_t  daylight, pad2;
} efi_time;

typedef struct {
    efi_table_header hdr;
    efi_status (*get_time)(efi_time *time, void *capabilities);
} efi_runtime_services;

typedef struct {
    efi_table_header hdr;
    char16 *firmware_vendor;
    uint32_t firmware_revision;
    efi_handle con_in_handle;
    efi_text_input *con_in;
    efi_handle con_out_handle;
    efi_text_output *con_out;
    efi_handle std_err_handle;
    efi_text_output *std_err;
    efi_runtime_services *runtime_services;
    efi_boot_services *boot_services;
    uint64_t table_count;
    efi_configuration_table *tables;
} efi_system_table;

typedef struct {
    uint32_t revision;
    efi_handle parent;
    efi_system_table *system_table;
    efi_handle device;
    void *file_path;
    void *reserved;
    uint32_t load_options_size;
    void *load_options;
    void *image_base;
    uint64_t image_size;
    uint32_t image_code_type, image_data_type;
    void *unload;
} efi_loaded_image;

typedef struct efi_file {
    uint64_t revision;
    efi_status (*open)(struct efi_file *self, struct efi_file **out, const char16 *name, uint64_t mode, uint64_t attributes);
    efi_status (*close)(struct efi_file *self);
    void *delete_file;
    efi_status (*read)(struct efi_file *self, uint64_t *size, void *buf);
    void *write;
    efi_status (*get_position)(struct efi_file *self, uint64_t *pos);
    efi_status (*set_position)(struct efi_file *self, uint64_t pos);
    void *get_info, *set_info, *flush;
} efi_file;
#define EFI_FILE_MODE_READ 1ull

typedef struct efi_simple_fs {
    uint64_t revision;
    efi_status (*open_volume)(struct efi_simple_fs *self, efi_file **root);
} efi_simple_fs;

enum { GOP_RGBX = 0, GOP_BGRX = 1, GOP_BITMASK = 2, GOP_BLT_ONLY = 3 };

typedef struct {
    uint32_t version;
    uint32_t width, height;
    uint32_t pixel_format;
    uint32_t red_mask, green_mask, blue_mask, reserved_mask;
    uint32_t pixels_per_scan_line;
} efi_gop_mode_info;

typedef struct {
    uint32_t max_mode;
    uint32_t mode;
    efi_gop_mode_info *info;
    uint64_t info_size;
    uint64_t fb_base;
    uint64_t fb_size;
} efi_gop_mode;

typedef struct efi_gop {
    void *query_mode, *set_mode, *blt;
    efi_gop_mode *mode;
} efi_gop;

/* TCG2 (TPM 2.0) protocol: only HashLogExtendEvent is used (measured boot, PCR 8). */
typedef struct efi_tcg2 {
    void *get_capability, *get_event_log;
    efi_status (*hash_log_extend_event)(struct efi_tcg2 *self, uint64_t flags, uint64_t data, uint64_t len, void *event);
    void *submit_command, *get_active_pcr_banks, *set_active_pcr_banks, *get_result_of_set;
} efi_tcg2;

typedef struct __attribute__((packed)) {
    uint32_t size;               /* whole structure */
    uint32_t header_size;        /* 14 */
    uint16_t header_version;     /* 1 */
    uint32_t pcr;
    uint32_t event_type;
    uint8_t  event[64];
} efi_tcg2_event;
#define EV_IPL 0x0Du

/* EFI_RNG_PROTOCOL: GetRNG with the default algorithm (KASLR entropy). */
typedef struct efi_rng {
    void *get_info;
    efi_status (*get_rng)(struct efi_rng *self, const efi_guid *algorithm, uint64_t len, uint8_t *out);
} efi_rng;

#define GUID_RNG          { 0x3152BCA5, 0xEADE, 0x433D, { 0x86, 0x2E, 0xC0, 0x1C, 0xDC, 0x29, 0x1F, 0x44 } }
#define GUID_TCG2         { 0x607F766C, 0x7455, 0x42BE, { 0x93, 0x0B, 0xE4, 0xD7, 0x6D, 0xB2, 0x72, 0x0F } }
#define GUID_LOADED_IMAGE { 0x5B1B31A1, 0x9562, 0x11D2, { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }
#define GUID_SIMPLE_FS    { 0x964E5B22, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }
#define GUID_GOP          { 0x9042A9DE, 0x23DC, 0x4A38, { 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A } }
#define GUID_ACPI_20      { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } }
#define GUID_ACPI_10      { 0xEB9D2D30, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }

#endif
