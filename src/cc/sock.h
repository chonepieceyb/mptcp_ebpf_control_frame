#ifndef CHONEPIECEYB_SOCK_H
#define CHONEPIECEYB_SOCK_H

#include<cstdint>
#include<cassert>
#include<type_traits>
#include "errors.h"
#include "utils.h"

#include <iostream>

extern "C" {
#include <sys/types.h>
#include <sys/socket.h>
}

namespace sock {

//对linux socket 系列的API做简单封装

template <typename Domain>
class SockAddr;

template <typename AddrType>
using is_sock_addr = std::is_same<AddrType, SockAddr<typename AddrType::domain_type>>;

//operator on socket

template<typename AddrType>
class SocketView {
public:
    using addr_type = AddrType;

    SocketView() {
        static_assert(is_sock_addr<AddrType>::value == true, "invalid AddrType for SocketView");
    }

    explicit SocketView(int fd) : _fd(fd) {
        static_assert(is_sock_addr<AddrType>::value == true, "invalid AddrType for SocketView");
    }

    virtual ~SocketView() = default;

    int fd() const {
        return _fd;
    }

    void reset(int nfd) {
        _fd = nfd;
    }

    template<typename ..._Types>
    void bind(_Types &&...args) const {
        _bind(AddrType(std::forward<_Types>(args)...));
    }

    void bind(const AddrType &sock_addr) const {
        _bind(sock_addr);
    }

    void listen(int backlog) const ;

    void connect(const AddrType &sock_addr) {
        _connect(sock_addr);
    }

    template<typename ..._Types>
    void connect(_Types &&...args) const {
        _connect(AddrType(std::forward<_Types>(args)...));
    }

    int accept(AddrType &accepted_addr) const;

    int accept() const;

    void setsockopt(int level, int optname,
        const void *optval, socklen_t optlen) const;

    std::size_t send(const char *buf, std::size_t len, int flags) const;

    std::size_t recv(char *buf, std::size_t len, int flags) const;

    //to be continue to support more easy to use API

protected:
    int _fd {-1};

private:
    void _bind(const AddrType &sock_addr) const;

    void _connect(const AddrType &sock_addr) const;
};

template<typename AddrType>
class Socket : public SocketView<AddrType> {
public:
    using view_type = SocketView<AddrType>;

    Socket(int type, int protocl);

    Socket(int fd);

    const view_type* view() {
        return dynamic_cast<const view_type*>(this);
    }

protected:
    utils::FdUPtr _fd_uptr;
};


template<typename AddrType>
void SocketView<AddrType>::_bind(const AddrType &sock_addr) const {
    int res = ::bind(_fd, reinterpret_cast<const sockaddr*>(&sock_addr), sizeof(typename AddrType::domain_type));

    if (res < 0) {
        throw errors::make_system_error("sock bind error!");
    }
}

template<typename AddrType>
void SocketView<AddrType>::_connect(const AddrType &sock_addr) const {
    int res = ::connect(_fd, reinterpret_cast<const sockaddr*>(&sock_addr), sizeof(typename AddrType::domain_type));
    if (res < 0) {
        throw errors::make_system_error("sock connect error!");
    }
}

template<typename AddrType>
int SocketView<AddrType>::accept(AddrType &accepted_addr) const {
    socklen_t len = sizeof(typename AddrType::domain_type);
    //should be used careful
    int nfd = ::accept(_fd, reinterpret_cast<sockaddr*>(&accepted_addr), &len);
    if (nfd < 0) {
        throw errors::make_system_error("sock accept error!");
    }
    return nfd;
}

template<typename AddrType>
void SocketView<AddrType>::listen(int backlog) const {
    int res = ::listen(_fd, backlog);
    if (res < 0) {
        throw errors::make_system_error("sock listen error!");
    }
}

template<typename AddrType>
int SocketView<AddrType>::accept() const {
    int nfd = ::accept(_fd, nullptr, nullptr);
    if (nfd < 0) {
        throw errors::make_system_error("sock accept error!");
    }
    return nfd;
}

template<typename AddrType>
void SocketView<AddrType>::setsockopt(
        int level, int optname, const void *optval, socklen_t optlen) const {
    int res = ::setsockopt(_fd, level, optname, optval, optlen);
    if (res == -1) {
        throw errors::make_system_error("set sock opt fail");
    }
}

template<typename AddrType>
std::size_t SocketView<AddrType>::send(
        const char *buf, std::size_t len, int flags) const {
    ssize_t send_size = ::send(_fd, buf, len, flags);
    if (send_size < 0) {
        throw errors::make_system_error("sock send error!");
    }
    return static_cast<std::size_t>(send_size);
}

template<typename AddrType>
std::size_t SocketView<AddrType>::recv(
        char *buf, std::size_t len, int flags) const {
    ssize_t recv_size = ::recv(_fd, buf, len, flags);
    if (recv_size < 0) {
        throw errors::make_system_error("sock recv error!");
    }
    return static_cast<std::size_t>(recv_size);
}


template<typename AddrType>
Socket<AddrType>::Socket(int type, int protocol) : SocketView<AddrType>() {
    int fd = socket(AddrType::domain_value, type, protocol);
    if (fd < 0) {
        throw errors::make_system_error("create socket faild");
    }
    _fd_uptr = utils::FdUPtr(new utils::FileDescriptor(fd));
    this->reset(_fd_uptr->fd);   //reset socket view
}

template<typename AddrType>
Socket<AddrType>::Socket(int fd) : SocketView<AddrType>(fd) {
    _fd_uptr = utils::FdUPtr(new utils::FileDescriptor(fd));
}

}
#endif
