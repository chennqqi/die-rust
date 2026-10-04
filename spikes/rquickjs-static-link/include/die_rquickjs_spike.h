#ifndef DIE_RQUICKJS_SPIKE_H
#define DIE_RQUICKJS_SPIKE_H

#include <stdint.h>

#define DIE_RQUICKJS_SPIKE_STATUS_OK UINT32_C(0)
#define DIE_RQUICKJS_SPIKE_STATUS_INVALID_ARGUMENT UINT32_C(1)
#define DIE_RQUICKJS_SPIKE_STATUS_RUNTIME_ERROR UINT32_C(2)
#define DIE_RQUICKJS_SPIKE_STATUS_PANIC UINT32_C(3)

#ifdef __cplusplus
extern "C" {
#endif

uint32_t die_rquickjs_spike_eval(int32_t *out_value);
uint32_t die_rquickjs_spike_force_panic(void);

#ifdef __cplusplus
}
#endif

#endif
