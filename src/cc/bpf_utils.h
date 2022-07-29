#ifndef CHONEPIECEYB_BPF_UTILS_H
#define CHONEPIECEYB_BPF_UTILS_H 

#include "errors.h"
#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <memory>

extern "C" {

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

}

namespace bpf {

inline int bpf_obj_get(const std::string &path) {
    int res = ::bpf_obj_get(path.data());
    if (res < 0) {
        throw errors::make_system_error("bpf obj get failed", res);
    }
    return res;
}

class BPFMapView {
public: 
    BPFMapView(int nfd = -1) : _fd(nfd) {};
    
    void reset(int nfd) {
        _fd = nfd;
    }
    
    int fd() {return _fd;}

    template<typename Key, typename Value,
        typename std::enable_if<std::is_standard_layout<Key>::value && 
        std::is_standard_layout<Value>::value, bool>::type = true
    >
    void lookup_elem(const Key &key, Value &value) {
        int res = ::bpf_map_lookup_elem(_fd, &key, &value);
        if (res < 0) {
            throw errors::make_system_error("bpf map look up elem failed", res);
        }
    }

    template<typename Key, 
        typename std::enable_if<std::is_standard_layout<Key>::value, bool>::type = true
    >
    void delete_elem(const Key &key) {
        int res = ::bpf_map_delete_elem(_fd, &key);
        if (res < 0) {
            throw errors::make_system_error("bpf map delete elem failed", res);
        }
    }

    template<typename Key, typename Value,
        typename std::enable_if<std::is_standard_layout<Key>::value && 
        std::is_standard_layout<Value>::value, bool>::type = true
    >
    void update_elem(const Key &key, const Value &value, std::uint64_t flags = 0) {
        int res = bpf_map_update_elem(_fd, &key, &value, flags);
        if (res < 0) {
            throw errors::make_system_error("bpf map update elem failed", res);
        }
    }

private:
    int _fd;

};

struct RawPerfBufferDelter {
    void operator()(struct perf_buffer *pb) {
        if (pb != nullptr) {
            perf_buffer__free(pb);
        }
    }
};

using RawPerfBufUPtr = std::unique_ptr<perf_buffer, RawPerfBufferDelter>;

class PerfBuffer {
public:
    using SampleCallBack = std::function<void(int, void*, std::uint32_t)>;  //call_back(cpu,data, size)
    using LostCallBack = std::function<void(int, std::uint64_t)>;  //call_back(cpu,data, size)

    SampleCallBack sample_cb;
    LostCallBack lost_cb;

    template<typename S_CB, typename L_CB>
    PerfBuffer(int map_fd, S_CB &&sample_cb, L_CB &&lost_cb, std::size_t page_cnt = 8); 

    void poll(const std::chrono::milliseconds &time_out);
private:
    static void _sample_cb_fn(void *ctx, int cpu, void *data, std::uint32_t size); //past this pointer as ctx 

    static void _lost_cb_fn(void *ctx, int cpu, unsigned long long cnt);

    RawPerfBufUPtr _pb;
};

template<typename S_CB, typename L_CB>
PerfBuffer::PerfBuffer(int map_fd, S_CB &&scb, L_CB &&lcb, std::size_t page_cnt) : sample_cb(std::forward(scb)), lost_cb(std::forward(lcb)) {
    struct perf_buffer *raw_pb;
    perf_buffer_sample_fn sample_cb_fn = nullptr;
    perf_buffer_lost_fn lost_cb_fn = nullptr;

    if (sample_cb) {
        sample_cb_fn = _sample_cb_fn;
    }
    if (lost_cb) {
        lost_cb_fn = _lost_cb_fn;
    }

    raw_pb = ::perf_buffer__new(map_fd, page_cnt, &PerfBuffer::_sample_cb_fn, &PerfBuffer::_lost_cb_fn, reinterpret_cast<void*>(this), nullptr); //use this ptr as ctx pointer 
    
    int res = ::libbpf_get_error(raw_pb);
    if (res < 0) {
        throw errors::ExceptionCode("open PerfBuffer failed", res);
    }
    _pb = RawPerfBufUPtr(raw_pb);
}


}


#endif 
