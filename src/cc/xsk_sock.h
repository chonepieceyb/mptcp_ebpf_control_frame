#ifndef eMPTCP_XSK_SOCK_H
#define eMPTCP_XSK_SOCK_H

#include <memory>
#include <cstring>
#include <vector>
#include <cassert>
#include "umem.h"
#include "errors.h"
#include "frame_allocator.h"
#include <iostream> 

//for debug 

extern "C" {
#include <xsk.h>
#include <poll.h>
#include <sys/socket.h>
}

namespace eMPTCP {

namespace xsk {

struct RawXSKSockDel {
    void operator()(struct xsk_socket *xsk) {
        if (xsk != nullptr) {
            xsk_socket__delete(xsk);
        }
    }
};

using RawXSKSockUPtr = std::unique_ptr<struct xsk_socket, RawXSKSockDel>;

struct XSKSocketConfig : public xsk_socket_config {
    XSKSocketConfig() {
        rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;  //2048
        tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS; //2048
        libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        xdp_flags = 0;
        bind_flags = XDP_USE_NEED_WAKEUP;
    }

    bool is_shared_umem() {
        return bind_flags & XDP_SHARED_UMEM;
    }

    bool need_wakeup() {
        return bind_flags & XDP_USE_NEED_WAKEUP;
    }

    xsk_socket_config *origin {dynamic_cast<xsk_socket_config*>(this)};
};

class XSKSocket {
public:
    XSKSocket(const std::string& ifname, 
        std::uint32_t queue_id, 
        const UmemSPtr &umem,
        const XSKSocketConfig &conf);
    
    ~XSKSocket();

    int fd() {
        return _fds[0].fd;
    }
    //receive as much frames as possible unblock
    template<typename OutputIt> 
    std::uint32_t recv(OutputIt out, std::uint32_t batch_size);

    //block 
    template<typename InputIt>
    void send(InputIt begin, std::uint32_t size);

    //fill at max num, num is set to actual num filled 
    std::uint32_t prodfr(std::uint32_t num);      //refill fill ring 

    std::uint32_t conscr(std::uint32_t num);    //cons as much as possible;

    std::uint64_t alloc_frame() {
        return _alloc->alloc();
    }
    
    void free_frame(std::uint64_t frame) {
        _alloc->free(frame);
    }
    
    template<typename InputIt> 
    void free_frames(InputIt begin, InputIt end) {
        _alloc->free(begin, end);
    }

private: 
    UmemSPtr _umem;
    XSKSocketConfig _conf;
    RawXSKSockUPtr _xsk_sock {nullptr};
    XSKFrSPtr _fr; 
    XSKCrSPtr _cr; 
    XSKTxRingUPtr _tx {nullptr};
    XSKRxRingUPtr _rx {nullptr};
    FrameAllocUPtr _alloc;

    int _outstanding {0};
    struct pollfd _fds[2];
};

//receive as much frames as possible
template<typename OutputIt> 
std::uint32_t XSKSocket::recv(OutputIt out, std::uint32_t batch_size) {
    assert((batch_size > 0) && "XSKSocket receive batch_size must > 0");
    
    int ret = 1;
    uint32_t size;

    while(true) {
	if (_conf.need_wakeup()) {
	    ret = poll(_fds, 1, -1);
	    if (ret <= 0 || ret > 1) {
		continue;
	    }
        }
        size = _rx->consume(out, batch_size);  //consume rx 
        if (size > 0) break;
    }
    //try to refill 
    prodfr(size);
    return size;
}

//block 
template<typename InputIt>
void XSKSocket::send(InputIt begin, std::uint32_t size) {
    if (size ==0) return;
    while(size > 0) {
        size -= _tx->try_produce(begin, size);;
        std::cout << "xsk send res : " << size << "\n";
        if (_conf.need_wakeup()) {
            sendto(fd(), NULL, 0, MSG_DONTWAIT, NULL, 0);  // should write like this ? 
        }
    }
    _outstanding = std::max(0, _outstanding);  //should not < 0
    _outstanding += size; 
    _outstanding -= conscr(_outstanding);
}

}

}
#endif 
