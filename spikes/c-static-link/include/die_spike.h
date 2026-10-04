#ifndef DIE_SPIKE_H
#define DIE_SPIKE_H

#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define DIE_SPIKE_ABI_VERSION UINT32_C(1)
#define DIE_SPIKE_STATUS_OK UINT32_C(0)
#define DIE_SPIKE_STATUS_INVALID_ARGUMENT UINT32_C(1)
#define DIE_SPIKE_STATUS_INPUT_TOO_LARGE UINT32_C(2)
#define DIE_SPIKE_STATUS_PANIC UINT32_C(3)
#define DIE_SPIKE_MAX_INPUT_BYTES UINT64_C(16777216)

typedef struct die_spike_result die_spike_result;

uint32_t die_spike_abi_version(void);

/*
 * Borrows data for this call and returns one Rust-owned opaque result.
 * A null data pointer is valid only when length is zero.
 * On failure, a non-null out_result is always written to null.
 * The caller must release a successful result with die_spike_result_free.
 */
uint32_t die_spike_scan(const uint8_t *data,
                         uint64_t length,
                         die_spike_result **out_result);

/*
 * Returns a non-NUL-terminated byte view borrowed from result.
 * The view is valid until the owning result is freed.
 */
uint32_t die_spike_result_json(const die_spike_result *result,
                                const uint8_t **out_data,
                                uint64_t *out_length);

/*
 * Releases Rust-owned memory and writes null to the caller's variable.
 * Passing the same now-null variable again is valid; passing a stale copy is
 * invalid. The caller must synchronize reads against freeing the result.
 */
uint32_t die_spike_result_free(die_spike_result **in_out_result);

/* Returns a static, non-NUL-terminated byte view that must not be freed. */
uint32_t die_spike_status_message(uint32_t status,
                                   const uint8_t **out_data,
                                   uint64_t *out_length);

/* Spike-only probe; intentionally panics internally and must return status 3. */
uint32_t die_spike_force_panic(void);

#if defined(__cplusplus)
}
#endif

#endif
