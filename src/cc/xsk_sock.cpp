#include "xsk_sock.h"
#include <cassert>
#include <cstring>
#include <iostream>

namespace eMPTCP {

namespace xsk {

XSKSocket::XSKSocket(const std::string& ifname, 
            std::uint32_t queue_id, 
            const UmemSPtr &umem,
            const XSKSocketConfig &conf) : _umem(umem), _conf(conf) {
    assert((_conf.rx_size > 0 || _conf.tx_size > 0) && "init XSKSocket tx or rx size must > 0");
    //alloc frames;
    auto frame_num = _conf.rx_size + _conf.tx_size;
    FrameAllocator::FrameContainer frames;
    _umem->try_alloc_frames(std::back_inserter(frames), frame_num);
    _alloc = FrameAllocUPtr(new FrameAllocator(std::move(frames)));

    if (_conf.is_shared_umem()) {
        _fr = std::make_shared<XSKFillRing>();
        _cr = std::make_shared<XSKCompleteRing>();
    } else {
        _fr = _umem->fr();
        _cr = _umem->cr();
    }
    int ret;
    struct xsk_ring_cons *rx = nullptr;
    struct xsk_ring_prod *tx = nullptr;
    if (_conf.rx_size > 0) {
        _rx = XSKRxRingUPtr(new XSKRxRing());
        rx = _rx->origin;
    }
    if (_conf.tx_size > 0) {
        _tx = XSKTxRingUPtr(new XSKTxRing());
        tx = _tx->origin;
    }
    struct xsk_socket *sock;
    ret = xsk_socket__create_shared(&sock, ifname.data(), queue_id, umem->get(), rx, tx, _fr->origin, _cr->origin, _conf.origin);
    if (ret != 0) {
        throw errors::make_system_error("XSKSocket init failed", -ret);
    }
    _xsk_sock = RawXSKSockUPtr(sock);
    std::memset(_fds, 0, sizeof(_fds));

    _fds[0].fd = xsk_socket__fd(_xsk_sock.get());
    _fds[0].events = POLLIN;
    
    //fill ring
    prodfr(_conf.rx_size);
}

XSKSocket::~XSKSocket() {
    //return frames to umem 
    try {
        FrameAllocator::InputIt begin, end;
        std::tie(begin, end) = _alloc->pre_clear();
        _umem->free_frames(begin, end);
        _alloc->submit_clear();
    } catch (...) {
        //nothing
    }
}

std::uint32_t XSKSocket::prodfr(std::uint32_t num) {
    FrameAllocator::InputIt in;
    std::tie(in, num) = _alloc->pre_alloc(num);
    num = _fr->try_produce(in, num);  //produce fill ring;
    if (_conf.need_wakeup()) {
        sendto(_umem->fd(), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    _alloc->submit_alloc(num);    //finish alloc
    return num;
}

std::uint32_t XSKSocket::conscr(std::uint32_t num) {
    return _cr->consume(_alloc->free(), num);
}

}

}
