#ifndef EMPTCP_FRAME_ALLOCTOR_H
#define EMPTCP_FRAME_ALLOCTOR_H

#include<vector>
#include<cstdint>
#include<iterator>
#include<memory>

#include "errors.h"

namespace eMPTCP {

namespace xsk {

class FrameAllocator {
public:
    using FrameContainer = std::vector<std::uint64_t>;
    using InputIt = std::vector<std::uint64_t>::reverse_iterator;

    template <typename __InputIt,
          typename std::enable_if<std::is_same<typename FrameContainer::value_type, typename std::iterator_traits<__InputIt>::value_type>::value, bool>::type = true
    >
    FrameAllocator(__InputIt begin, __InputIt end) {
        _frames.insert(_frames.end(), begin, end);       
        _free_frames = _frames;
    }

    explicit FrameAllocator(FrameContainer && c) {
        _frames = std::move(c);
        _free_frames = _frames;
    }

    std::uint32_t capacity() {
        return static_cast<std::uint32_t>(_frames.size());
    }

    void clear(FrameContainer &out) {
        _free_frames.clear();
        out.clear();
        out.swap(_frames);
    }

    template<typename OutputIt>
    void clear(OutputIt out) {
        _free_frames.clear();
        std::move(_frames.begin(), _frames.end(), out);
        _frames.clear();
    }

    std::pair<InputIt, InputIt> pre_clear() {
        return std::make_pair(_frames.rbegin(), _frames.rend());
    };

    void submit_clear() {
        _free_frames.clear();
        _frames.clear();
    }

    std::uint32_t size() {
        return static_cast<std::uint32_t>(_free_frames.size());
    }

    std::uint64_t alloc() {
        if (_free_frames.empty()) {
            throw errors::InvalidFrame();
        }
        auto frame = _free_frames.back();
        _free_frames.pop_back();
        return frame;
    }
    
    template<typename OutputIt>
    void alloc(OutputIt out, std::uint32_t num);

    //try to alloc size
    std::pair<InputIt, std::uint32_t> pre_alloc(std::uint32_t num) {
        num = std::min(num, size());
        return std::make_pair(_free_frames.rbegin(), num);
    };

    void submit_alloc(std::uint32_t num) {
        for (std::uint32_t i = 0; i < num ; i++) {
            _free_frames.pop_back();
        }
    }

    template<typename OutputIt>
    std::uint32_t try_alloc(OutputIt out, std::uint32_t num) {
        num = std::min(num, size());
        alloc(out, num);
        return num;
    }

    void free(std::uint64_t frame) {
        _free_frames.push_back(frame);
    }
    
    template<typename __InputIt> 
    void free(__InputIt begin, __InputIt end);

    typename std::back_insert_iterator<FrameContainer> free() {
        return back_inserter(_free_frames);
    }

private:
    FrameContainer _free_frames;
    FrameContainer _frames;         //all frames
};

template<typename OutputIt>
void FrameAllocator::alloc(OutputIt out, std::uint32_t num) {
    if (_free_frames.size() < num) {
        throw errors::InvalidFrame();
    }
    for (std::uint32_t i = 0; i < num; i++) {
        *out++ = _free_frames.back();
        _free_frames.pop_back();
    }
}

template<typename __InputIt> 
void FrameAllocator::free(__InputIt begin, __InputIt end) {
    for(auto iter = begin; iter != end; iter++) {
        _free_frames.push_back(*iter);
    }
}

using FrameAllocUPtr = std::unique_ptr<FrameAllocator>;

}

}

#endif 
