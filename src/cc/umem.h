#ifndef EMPTCP_UMEM_H
#define EMPTCP_UMEM_H

#include<cstdint>
#include<memory>
#include<vector> 
#include<mutex>
#include<iterator>
#include<iostream>

extern "C" {
#include <xsk.h>
}

#include "utils.h"
#include "xsk_rings.h"
#include "frame_allocator.h"

namespace eMPTCP {

namespace xsk {

struct UmemConfig : public xsk_umem_config { 
    UmemConfig() {
        fill_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;  //2048
        comp_size = XSK_RING_PROD__DEFAULT_NUM_DESCS; //2048
        frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;  //4096
        frame_headroom =  XSK_UMEM__DEFAULT_FRAME_HEADROOM; //0
        flags = XSK_UMEM__DEFAULT_FLAGS; //0

        frames = fill_size + comp_size;
        buf_size = frames * frame_size;
    };
    
    std::uint32_t frames;
    union {
        std::uint64_t buf_size;
        std::uint64_t invalid_frame;
    };
    xsk_umem_config *origin {dynamic_cast<xsk_umem_config*>(this)};
};

struct RawUmemDeleter {
    void operator()(struct xsk_umem *umem) {
        if (umem != nullptr) {
            xsk_umem__delete(umem);
        }
    }
};

using RawUmemUPtr = std::unique_ptr<struct xsk_umem, RawUmemDeleter>;

class Umem {
public:
    Umem(const UmemConfig &config);

    struct xsk_umem* get() {
        return _umem.get();
    }
    
    XSKFrSPtr& fr()  {
        return _fr;
    }

    XSKCrSPtr& cr() {
        return _cr;
    }
    
    int fd() {
        return _fd;
    }

    std::size_t size();

    template<typename OutputIt> 
    std::uint32_t try_alloc_frames(OutputIt out, std::uint32_t num);
        
    template<typename InputIt>
    void free_frames(InputIt begin, InputIt end);
      
    void *get_data(std::uint64_t addr) {
        return xsk_umem__get_data(_buf, addr);
    }
private:
    std::mutex _mtx;
    UmemConfig _conf;
    XSKFrSPtr _fr; 
    XSKCrSPtr _cr;
    RawUmemUPtr _umem;
    FrameAllocUPtr _alloc;
    void *_buf;
    int _fd;
};

using UmemSPtr = std::shared_ptr<Umem>;

template<typename OutputIt> 
std::uint32_t Umem::try_alloc_frames(OutputIt out, std::uint32_t num) {
    std::lock_guard<std::mutex> lock(_mtx);
    return _alloc->try_alloc(out, num);
}

template<typename InputIt>
void Umem::free_frames(InputIt begin, InputIt end) {
     std::lock_guard<std::mutex> lock(_mtx);
    _alloc->free(begin, end);
}

}

}

#endif 
