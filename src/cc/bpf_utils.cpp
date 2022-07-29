#include "bpf_utils.h"

namespace bpf {
 
void PerfBuffer::poll(const std::chrono::milliseconds &time_out) {
    ::perf_buffer__poll(_pb.get(), time_out.count());
}

void PerfBuffer::_sample_cb_fn(void *ctx, int cpu, void *data, std::uint32_t size) {
    if (ctx == nullptr) {
        return;
    }
    auto *obj = reinterpret_cast<PerfBuffer*>(ctx);
    obj->sample_cb(cpu, data, size);
}

void PerfBuffer::_lost_cb_fn(void *ctx, int cpu, unsigned long long cnt) {
    if (ctx == nullptr) {
        return;
    }
    auto *obj = reinterpret_cast<PerfBuffer*>(ctx);
    obj->lost_cb(cpu, cnt);
}

}
