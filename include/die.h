#ifndef DIE_H
#define DIE_H

/*
 * die.h - Public C ABI for die-rust.
 *
 * This header defines the stable C ABI for the Detect-It-Easy-compatible
 * file identification engine. It uses opaque handles, explicit ownership
 * and paired pointer-to-pointer free functions.
 *
 * See docs/design/c-abi.md for the full design rationale.
 */

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

/* ---- ABI version ---- */

#define DIE_ABI_VERSION_ENCODE(major, minor) \
    ((((uint32_t)(major)) << 16) | ((uint32_t)(minor)))
#define DIE_ABI_V1_0 DIE_ABI_VERSION_ENCODE(1, 0)

/* ---- Status codes ---- */

#define DIE_STATUS_OK                 UINT32_C(0)
#define DIE_STATUS_INVALID_ARGUMENT   UINT32_C(1)
#define DIE_STATUS_ABI_MISMATCH       UINT32_C(2)
#define DIE_STATUS_INVALID_UTF8       UINT32_C(3)
#define DIE_STATUS_IO                 UINT32_C(4)
#define DIE_STATUS_DATABASE           UINT32_C(5)
#define DIE_STATUS_UNSUPPORTED        UINT32_C(6)
#define DIE_STATUS_LIMIT_EXCEEDED     UINT32_C(7)
#define DIE_STATUS_CANCELLED          UINT32_C(8)
#define DIE_STATUS_TIMEOUT            UINT32_C(9)
#define DIE_STATUS_SCRIPT             UINT32_C(10)
#define DIE_STATUS_WRONG_THREAD       UINT32_C(11)
#define DIE_STATUS_BUSY               UINT32_C(12)
#define DIE_STATUS_PANIC              UINT32_C(13)
#define DIE_STATUS_INTERNAL           UINT32_C(14)
#define DIE_STATUS_ALLOCATION_FAILED  UINT32_C(15)

/* ---- Database kinds ---- */

#define DIE_DATABASE_KIND_MAIN   UINT32_C(0)
#define DIE_DATABASE_KIND_EXTRA  UINT32_C(1)
#define DIE_DATABASE_KIND_CUSTOM UINT32_C(2)

/* ---- Scan option flags ---- */

#define DIE_SCAN_FLAG_DEEP          UINT32_C(0x00000001)
#define DIE_SCAN_FLAG_HEURISTIC     UINT32_C(0x00000002)
#define DIE_SCAN_FLAG_ALL_TYPES     UINT32_C(0x00000004)
#define DIE_SCAN_FLAG_AGGRESSIVE    UINT32_C(0x00000008)
#define DIE_SCAN_FLAG_HIDE_UNKNOWN  UINT32_C(0x00000010)
#define DIE_SCAN_FLAG_VERBOSE       UINT32_C(0x00000020)
#define DIE_SCAN_FLAG_NO_DEDUP      UINT32_C(0x00000040)
/* ADR 0028: intra-file recursive scanning flags */
#define DIE_SCAN_FLAG_RECURSIVE     UINT32_C(0x00000080)
#define DIE_SCAN_FLAG_RESOURCES     UINT32_C(0x00000100)
#define DIE_SCAN_FLAG_OVERLAYS      UINT32_C(0x00000200)
#define DIE_SCAN_FLAG_ARCHIVES      UINT32_C(0x00000400)

/* ---- Opaque handle types ---- */

typedef uint32_t die_status_t;

typedef struct die_v1_database_builder die_v1_database_builder;
typedef struct die_v1_database         die_v1_database;
typedef struct die_v1_scanner          die_v1_scanner;
typedef struct die_v1_cancel           die_v1_cancel;
typedef struct die_v1_result           die_v1_result;
typedef struct die_v1_error            die_v1_error;

/* ---- Scan options (by-value struct, additive extension via struct_size) ---- */

typedef struct die_v1_scan_options {
    uint32_t struct_size;
    uint32_t flags;
    uint64_t max_input_bytes;
    uint64_t max_unpacked_bytes;
    uint64_t max_container_entries;
    uint64_t timeout_ms;
    uint32_t max_recursion_depth;
    uint32_t reserved_0;
    uint64_t max_total_allocation_bytes;
    uint64_t script_heap_bytes;
    uint64_t script_stack_bytes;
    uint64_t script_fuel_quanta;
    uint64_t script_deadline_ms;
} die_v1_scan_options;

/* ---- ABI version negotiation ---- */

uint32_t die_abi_version(void);
uint32_t die_abi_is_compatible(uint32_t requested);

/* ---- Status name lookup ---- */

uint32_t die_v1_status_name(uint32_t status,
                             const uint8_t **out_data,
                             uint64_t *out_length);

/* ---- Scan options init ---- */

uint32_t die_v1_scan_options_init(die_v1_scan_options *options,
                                   uint32_t options_size);

/* ---- Database builder ---- */

uint32_t die_v1_database_builder_new(
    die_v1_database_builder **out_builder,
    die_v1_error **out_error);

uint32_t die_v1_database_builder_add_path_utf8(
    die_v1_database_builder *builder,
    uint32_t database_kind,
    const uint8_t *path,
    uint64_t path_length,
    uint32_t source_flags,
    die_v1_error **out_error);

uint32_t die_v1_database_builder_build(
    const die_v1_database_builder *builder,
    die_v1_database **out_database,
    die_v1_error **out_error);

uint32_t die_v1_database_builder_free(
    die_v1_database_builder **in_out_builder);

/* ---- Database ---- */

uint32_t die_v1_database_metadata_json(
    const die_v1_database *database,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t die_v1_database_free(
    die_v1_database **in_out_database);

/* ---- Cancel token ---- */

uint32_t die_v1_cancel_new(
    die_v1_cancel **out_cancel,
    die_v1_error **out_error);

uint32_t die_v1_cancel_request(die_v1_cancel *cancel);

uint32_t die_v1_cancel_free(die_v1_cancel **in_out_cancel);

/* ---- One-shot scan (thread-neutral) ---- */

uint32_t die_v1_scan_bytes(
    const die_v1_database *database,
    const uint8_t *data,
    uint64_t length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

uint32_t die_v1_scan_path_utf8(
    const die_v1_database *database,
    const uint8_t *path,
    uint64_t path_length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

/* ---- Reusable scanner ---- */

uint32_t die_v1_scanner_new(
    const die_v1_database *database,
    die_v1_scanner **out_scanner,
    die_v1_error **out_error);

uint32_t die_v1_scanner_scan_bytes(
    die_v1_scanner *scanner,
    const uint8_t *data,
    uint64_t length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

uint32_t die_v1_scanner_scan_path_utf8(
    die_v1_scanner *scanner,
    const uint8_t *path,
    uint64_t path_length,
    const die_v1_scan_options *options,
    const die_v1_cancel *cancel,
    die_v1_result **out_result,
    die_v1_error **out_error);

uint32_t die_v1_scanner_free(
    die_v1_scanner **in_out_scanner);

/* ---- Result accessors ---- */

uint32_t die_v1_result_json(
    const die_v1_result *result,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t die_v1_result_path_utf8(
    const die_v1_result *result,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t die_v1_result_detection_count(
    const die_v1_result *result,
    uint64_t *out_count);

uint32_t die_v1_result_free(
    die_v1_result **in_out_result);

/* ---- Error accessors ---- */

uint32_t die_v1_error_status(
    const die_v1_error *error,
    uint32_t *out_status);

uint32_t die_v1_error_message(
    const die_v1_error *error,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t die_v1_error_free(
    die_v1_error **in_out_error);

#if defined(__cplusplus)
}
#endif

#endif /* DIE_H */
