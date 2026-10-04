#include "../include/die_rquickjs_spike.h"

#include <assert.h>
#include <stddef.h>

int main(void)
{
    int32_t value = 0;

    assert(
        die_rquickjs_spike_eval(NULL)
        == DIE_RQUICKJS_SPIKE_STATUS_INVALID_ARGUMENT
    );
    for (int index = 0; index < 16; ++index) {
        value = 0;
        assert(
            die_rquickjs_spike_eval(&value)
            == DIE_RQUICKJS_SPIKE_STATUS_OK
        );
        assert(value == 42);
    }
    assert(
        die_rquickjs_spike_force_panic()
        == DIE_RQUICKJS_SPIKE_STATUS_PANIC
    );
    return 0;
}
