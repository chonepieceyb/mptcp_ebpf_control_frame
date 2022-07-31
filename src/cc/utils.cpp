#include "utils.h" 

#include<cassert>
#include<cstring>
#include<iostream>

extern "C" {
#include<malloc.h> 
} 

namespace utils {

BufUPtr create_buffer(std::size_t size, bool init = true) {
    assert((size > 0)&&"create_buffer buffer len must > 0");
    void *ptr = std::malloc(size);
    if (ptr == nullptr) {
        throw errors::make_system_error("create_buffer failed");
    }
    if (init) {
        std::memset(ptr, 0, size);
    }
    return BufUPtr(ptr);
}

BufUPtr create_align_buffer(std::size_t alignment, std::size_t size, bool init = true) {
    assert((size > 0)&&"create_align_buffer buffer len must > 0");
    void *ptr = memalign(alignment, size);
    if (ptr == nullptr) {
        throw errors::make_system_error("create_align_buffer failed");
    }
    if (init) {
        std::memset(ptr, 0, size);
    }
    return BufUPtr(ptr);
}


}
