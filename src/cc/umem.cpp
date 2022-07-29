#include "umem.h" 
#include "errors.h"
#include "utils.h"

namespace eMPTCP {

namespace xsk {

Umem::Umem(const UmemConfig &config) : _conf(config) {
    auto buf = utils::create_align_buffer(_conf.frame_size, _conf.buf_size, true);
    int ret;
    struct xsk_umem *u;
    _fr = std::make_shared<XSKFillRing>();
    _cr = std::make_shared<XSKCompleteRing>();
    _buf = buf.release();
    ret = xsk_umem__create(&u, _buf, _conf.buf_size, _fr->origin, _cr->origin, _conf.origin);
    if (ret != 0) {
        //if xsk_umem__create failed, the funtion will free buf
        //just throw exception
        throw errors::make_system_error("Umem init failed, xsk_umem__create failed", -ret);
    }
    _umem = RawUmemUPtr(u);
    //add frames
    FrameAllocator::FrameContainer frames;
    auto out = std::back_inserter(frames);
    for (auto i = 0; i < _conf.frames; i++) {
        *out++ = i * _conf.frame_size;
    }
    _alloc = FrameAllocUPtr(new FrameAllocator(std::move(frames)));
    _fd = xsk_umem__fd(_umem.get());
}
    
std::size_t Umem::size() {
    std::lock_guard<std::mutex> lock(_mtx);
    return _alloc->size();
}

}

}
