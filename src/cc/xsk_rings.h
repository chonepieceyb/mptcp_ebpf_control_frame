#ifndef EMPTCP_XSK_RING_H
#define EMPTCP_XSK_RING_H

extern "C" {
#include <xsk.h>
}

#include<cstdint>
#include<type_traits>
#include<iterator>
#include<memory>

//fordebug
#include<iostream>

namespace eMPTCP {

namespace xsk {

//idx, size
using XSKRingPair = std::pair<std::uint32_t, std::uint32_t>;

struct XDPDesc : public xdp_desc {
    XDPDesc(std::uint64_t a, std::uint32_t l, std::uint32_t o) {
        addr = a; 
        len = l;
        options = o;
    }
};

template<typename Consumer>
class XSKConsRing : public xsk_ring_cons {
public:
    std::uint32_t nb_avail(std::uint32_t nb) {
        return xsk_cons_nb_avail(origin, nb);
    }  
    
    XSKRingPair peek(std::uint32_t nb) {
        std::uint32_t idx, avail;
	idx = 0;
        avail = xsk_ring_cons__peek(origin, nb, &idx);
        return std::make_pair(idx, avail);
    }

    void release(std::uint32_t nb) {
        xsk_ring_cons__release(origin, nb);
    }
    
    template<typename OutputIt>
    std::uint32_t consume(OutputIt out, std::uint32_t size); 

    xsk_ring_cons *origin {dynamic_cast<xsk_ring_cons*>(this)};
};

template<typename Producer>
class XSKProdRing : public xsk_ring_prod {
public:
    std::uint32_t nb_free(std::uint32_t nb) {
        return xsk_prod_nb_free(origin, nb);
    }

    XSKRingPair reserve(std::uint32_t nb) {
        std::uint32_t idx, avail;
        avail = xsk_ring_prod__reserve(origin, nb, &idx);
        return std::make_pair(idx, avail);
    }

    bool need_wakeup() {
        return xsk_ring_prod__needs_wakeup(origin);
    }

    void submit(std::uint32_t nb) {
        xsk_ring_prod__submit(origin, nb);
    }
    
    //produce exactly at size, if fail return false, will not block
    template<typename InputIt>
    bool produce(InputIt begin, std::uint32_t size);

    //produce  at max size, return the actual produce size 
    template<typename InputIt>
    std::uint32_t try_produce(InputIt begin, std::uint32_t size) {
        std::uint32_t avail = nb_free(size);   
        if (avail == 0) return 0;
        avail = std::min(avail, size);
        if (!produce(begin, avail)) return 0;  //should not happen 
        return avail;
    }
    
    xsk_ring_prod *origin {dynamic_cast<xsk_ring_prod*>(this)};
};

class XSXFillRingProducer {
public:
    template <typename InputIt,
          typename std::enable_if<std::is_same<std::uint64_t, typename std::iterator_traits<InputIt>::value_type>::value, bool>::type = true
    >
    static void produce(struct xsk_ring_prod *origin, std::uint32_t idx, InputIt in) {
        *xsk_ring_prod__fill_addr(origin, idx) = *in;
    }
};

using XSKFillRing = XSKProdRing<XSXFillRingProducer>;
using XSKFrUPtr = std::unique_ptr<XSKFillRing>;
using XSKFrSPtr = std::shared_ptr<XSKFillRing>;

class XSKCompleteRingConsumer {
public:
    /*
    template <typename OutputIt,
          typename std::enable_if<std::is_same<std::uint64_t, typename std::iterator_traits<OutputIt>::value_type>::value, bool>::type = true
    >
    */
    template <typename OutputIt>
    static void consume(struct xsk_ring_cons* origin, OutputIt out, std::uint32_t idx) {
        *out = *xsk_ring_cons__comp_addr(origin, idx++);
    }
};

using XSKCompleteRing = XSKConsRing<XSKCompleteRingConsumer>;
using XSKCrUPtr = std::unique_ptr<XSKCompleteRing>;
using XSKCrSPtr = std::shared_ptr<XSKCompleteRing>;

class XSKTxRingProducer {
public: 
    template <typename InputIt,
          typename std::enable_if<std::is_same<XDPDesc, typename std::iterator_traits<InputIt>::value_type>::value, bool>::type = true
    >
    static void produce(struct xsk_ring_prod *origin, std::uint32_t idx, InputIt in) {
        struct xdp_desc *desc;
        desc = xsk_ring_prod__tx_desc(origin, idx);
        desc->addr = in->addr;
        desc->len = in->len;
        desc->options = in->options;
    }
};

using XSKTxRing = XSKProdRing<XSKTxRingProducer>;
using XSKTxRingUPtr = std::unique_ptr<XSKTxRing>;

class XSKRxRingConsumer {
public: 
   /*
   template <typename OutputIt,
          typename std::enable_if<std::is_same<XDPDesc, typename std::iterator_traits<OutputIt>::value_type>::value, bool>::type = true
    >
*/
    template<typename OutputIt>
    static void consume(struct xsk_ring_cons *origin, OutputIt out, std::uint32_t idx) {
        const struct xdp_desc *desc =  xsk_ring_cons__rx_desc(origin, idx);
        *out = XDPDesc(desc->addr, desc->len, desc->options);
    }
};

using XSKRxRing = XSKConsRing<XSKRxRingConsumer>;
using XSKRxRingUPtr = std::unique_ptr<XSKRxRing>;


template<typename Consumer>
template<typename OutputIt>
std::uint32_t XSKConsRing<Consumer>::consume(OutputIt out, std::uint32_t size) {
    std::uint32_t idx,avail;
    std::tie(idx, avail) = peek(size);
    if (avail == 0) return 0;
    for (std::uint32_t i = 0; i< avail; i++) {
        Consumer::consume(origin, out++, idx++);
    }
    release(avail);
    return avail;
}

template<typename Producer>
template<typename InputIt>
bool XSKProdRing<Producer>::produce(InputIt begin, std::uint32_t size) {
    std::uint32_t idx; 
    std::uint32_t avail;
    std::tie(idx, avail) = reserve(size);
    if (avail == 0) return false;
    for (std::uint32_t i = 0; i < avail; i++) {
        Producer::produce(origin, idx++, begin++);
    }
    submit(avail);
    return true;
}

}

}
#endif 
