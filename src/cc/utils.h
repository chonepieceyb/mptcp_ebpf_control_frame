#ifndef EMPTCP_UTILS_H
#define EMPTCP_UTILS_H

#include<cstdlib>
#include<memory> 
#include<cstdint> 
#include<functional>
#include<csignal>
#include "errors.h"

extern "C" {
#include <unistd.h>
}

namespace utils {

class FileDescriptor {
public:    
    explicit FileDescriptor(int nfd = -1) : fd(nfd) {
    }
    ~FileDescriptor() {
        if (fd >= 0) close(fd);
    }
    int fd;
};

using FdUPtr = std::unique_ptr<FileDescriptor>;
using FdSPtr = std::shared_ptr<FileDescriptor>;

struct BufferDeleter {
    void operator()(void* buf) {
        if (buf != nullptr) {
            std::free(buf);
        }
    };
};

using BufUPtr = std::unique_ptr<void, BufferDeleter>;

BufUPtr create_buffer(std::size_t size, bool init);

BufUPtr create_align_buffer(std::size_t alignment, std::size_t size, bool init);

class TermSignal {
public:
    static void regist() {
        std::signal(SIGINT, _sig_handler);
    }
private:
    static void _sig_handler(int sig) {
        if (sig == SIGINT) {
            throw errors::KeyboardInterrupt();
        }
    }
};

}

#endif 
