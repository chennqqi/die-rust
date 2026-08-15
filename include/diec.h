#ifndef DIEC_H
#define DIEC_H

/*
 * diec.h - Public C ABI for diec-rust.
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

#define DIEC_ABI_VERSION_ENCODE(major, minor) \
    ((((uint32_t)(major)) << 16) | ((uint32_t)(minor)))
#define DIEC_ABI_V1_0 DIEC_ABI_VERSION_ENCODE(1, 0)

/* ---- Status codes ---- */

#define DIEC_STATUS_OK                 UINT32_C(0)
#define DIEC_STATUS_INVALID_ARGUMENT   UINT32_C(1)
#define DIEC_STATUS_ABI_MISMATCH       UINT32_C(2)
#define DIEC_STATUS_INVALID_UTF8       UINT32_C(3)
#define DIEC_STATUS_IO                 UINT32_C(4)
#define DIEC_STATUS_DATABASE           UINT32_C(5)
#define DIEC_STATUS_UNSUPPORTED        UINT32_C(6)
#define DIEC_STATUS_LIMIT_EXCEEDED     UINT32_C(7)
#define DIEC_STATUS_CANCELLED          UINT32_C(8)
#define DIEC_STATUS_TIMEOUT            UINT32_C(9)
#define DIEC_STATUS_SCRIPT             UINT32_C(10)
#define DIEC_STATUS_WRONG_THREAD       UINT32_C(11)
#define DIEC_STATUS_BUSY               UINT32_C(12)
#define DIEC_STATUS_PANIC              UINT32_C(13)
#define DIEC_STATUS_INTERNAL           UINT32_C(14)
#define DIEC_STATUS_ALLOCATION_FAILED  UINT32_C(15)

/* ---- Database kinds ---- */

#define DIEC_DATABASE_KIND_MAIN   UINT32_C(0)
#define DIEC_DATABASE_KIND_EXTRA  UINT32_C(1)
#define DIEC_DATABASE_KIND_CUSTOM UINT32_C(2)

/* ---- Scan option flags ---- */

#define DIEC_SCAN_FLAG_DEEP          UINT32_C(0x00000001)
#define DIEC_SCAN_FLAG_HEURISTIC     UINT32_C(0x00000002)
#define DIEC_SCAN_FLAG_ALL_TYPES     UINT32_C(0x00000004)
#define DIEC_SCAN_FLAG_AGGRESSIVE    UINT32_C(0x00000008)
#define DIEC_SCAN_FLAG_HIDE_UNKNOWN  UINT32_C(0x00000010)
#define DIEC_SCAN_FLAG_VERBOSE       UINT32_C(0x00000020)
#define DIEC_SCAN_FLAG_NO_DEDUP      UINT32_C(0x00000040)
/* ADR 0028: intra-file recursive scanning flags */
#define DIEC_SCAN_FLAG_RECURSIVE     UINT32_C(0x00000080)
#define DIEC_SCAN_FLAG_RESOURCES     UINT32_C(0x00000100)
#define DIEC_SCAN_FLAG_OVERLAYS      UINT32_C(0x00000200)
#define DIEC_SCAN_FLAG_ARCHIVES      UINT32_C(0x00000400)

/* ---- Opaque handle types ---- */

typedef uint32_t diec_status_t;

typedef struct diec_v1_database_builder diec_v1_database_builder;
typedef struct diec_v1_database         diec_v1_database;
typedef struct diec_v1_scanner          diec_v1_scanner;
typedef struct diec_v1_cancel           diec_v1_cancel;
typedef struct diec_v1_result           diec_v1_result;
typedef struct diec_v1_error            diec_v1_error;

/* ---- Scan options (by-value struct, additive extension via struct_size) ---- */

typedef struct diec_v1_scan_options {
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
} diec_v1_scan_options;

/* ---- ABI version negotiation ---- */

uint32_t diec_abi_version(void);
uint32_t diec_abi_is_compatible(uint32_t requested);

/* ---- Status name lookup ---- */

uint32_t diec_v1_status_name(uint32_t status,
                             const uint8_t **out_data,
                             uint64_t *out_length);

/* ---- Scan options init ---- */

uint32_t diec_v1_scan_options_init(diec_v1_scan_options *options,
                                   uint32_t options_size);

/* ---- Database builder ---- */

uint32_t diec_v1_database_builder_new(
    diec_v1_database_builder **out_builder,
    diec_v1_error **out_error);

uint32_t diec_v1_database_builder_add_path_utf8(
    diec_v1_database_builder *builder,
    uint32_t database_kind,
    const uint8_t *path,
    uint64_t path_length,
    uint32_t source_flags,
    diec_v1_error **out_error);

uint32_t diec_v1_database_builder_build(
    const diec_v1_database_builder *builder,
    diec_v1_database **out_database,
    diec_v1_error **out_error);

uint32_t diec_v1_database_builder_free(
    diec_v1_database_builder **in_out_builder);

/* ---- Database ---- */

uint32_t diec_v1_database_metadata_json(
    const diec_v1_database *database,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t diec_v1_database_free(
    diec_v1_database **in_out_database);

/* ---- Cancel token ---- */

uint32_t diec_v1_cancel_new(
    diec_v1_cancel **out_cancel,
    diec_v1_error **out_error);

uint32_t diec_v1_cancel_request(diec_v1_cancel *cancel);

uint32_t diec_v1_cancel_free(diec_v1_cancel **in_out_cancel);

/* ---- One-shot scan (thread-neutral) ---- */

uint32_t diec_v1_scan_bytes(
    const diec_v1_database *database,
    const uint8_t *data,
    uint64_t length,
    const diec_v1_scan_options *options,
    const diec_v1_cancel *cancel,
    diec_v1_result **out_result,
    diec_v1_error **out_error);

uint32_t diec_v1_scan_path_utf8(
    const diec_v1_database *database,
    const uint8_t *path,
    uint64_t path_length,
    const diec_v1_scan_options *options,
    const diec_v1_cancel *cancel,
    diec_v1_result **out_result,
    diec_v1_error **out_error);

/* ---- Reusable scanner ---- */

uint32_t diec_v1_scanner_new(
    const diec_v1_database *database,
    diec_v1_scanner **out_scanner,
    diec_v1_error **out_error);

uint32_t diec_v1_scanner_scan_bytes(
    diec_v1_scanner *scanner,
    const uint8_t *data,
    uint64_t length,
    const diec_v1_scan_options *options,
    const diec_v1_cancel *cancel,
    diec_v1_result **out_result,
    diec_v1_error **out_error);

uint32_t diec_v1_scanner_scan_path_utf8(
    diec_v1_scanner *scanner,
    const uint8_t *path,
    uint64_t path_length,
    const diec_v1_scan_options *options,
    const diec_v1_cancel *cancel,
    diec_v1_result **out_result,
    diec_v1_error **out_error);

uint32_t diec_v1_scanner_free(
    diec_v1_scanner **in_out_scanner);

/* ---- Result accessors ---- */

uint32_t diec_v1_result_json(
    const diec_v1_result *result,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t diec_v1_result_path_utf8(
    const diec_v1_result *result,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t diec_v1_result_detection_count(
    const diec_v1_result *result,
    uint64_t *out_count);

uint32_t diec_v1_result_free(
    diec_v1_result **in_out_result);

/* ---- Error accessors ---- */

uint32_t diec_v1_error_status(
    const diec_v1_error *error,
    uint32_t *out_status);

uint32_t diec_v1_error_message(
    const diec_v1_error *error,
    const uint8_t **out_data,
    uint64_t *out_length);

uint32_t diec_v1_error_free(
    diec_v1_error **in_out_error);

#if defined(__cplusplus)
}
#endif

#endif /* DIEC_H */
