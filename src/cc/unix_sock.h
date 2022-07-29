#ifndef CHONEPIECEYB_UNIX_SOCK_H
#define CHONEPIECEYB_UNIX_SOCK_H

#include <cstring>
#include <string>
#include <ostream>
#include <algorithm>
#include "sock.h"
#include "utils.h"

extern "C" {

#include <sys/socket.h>
#include <sys/un.h>

}

namespace sock {

template <> 
class SockAddr<sockaddr_un> : public sockaddr_un {
public:
    const static int domain_value = AF_UNIX;

    using domain_type = sockaddr_un;

    SockAddr() {
        std::memset(this, 0, sizeof(sockaddr_un));
        sun_family = domain_value;
    }
    SockAddr(const std::string &path) {
        sun_family = domain_value;
        std::memset(sun_path, 0, sizeof(sun_path));
        std::strncpy(sun_path, path.data(), std::min(sizeof(sun_path), path.length()));
    }

    SockAddr &operator=(const SockAddr &other) {
        std::memcpy(sun_path, other.sun_path, sizeof(sun_path));
        return *this;
    }

    friend std::ostream& operator<<(std::ostream &out, const SockAddr &sock) {
        out << "sun_path: " << sock.sun_path;
        return out;
    }
};

using SockAddrUn = SockAddr<sockaddr_un>;

class UnixSock : public Socket<SockAddrUn> {
public: 
    explicit UnixSock(int type = SOCK_SEQPACKET) : Socket<SockAddrUn> (type, 0) {
    };
    
private: 
    utils::FdUPtr _fd;
};

}

#endif 
