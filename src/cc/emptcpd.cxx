#ifndef EMPTCP_EMPTCPD_H
#define EMPTCP_EMPTCPD_H

#include <string> 
#include <list>
#include "umem.h"
#include "xsk_sock.h"
#include "xsk_rings.h"
#include "sock.h"
#include "unix_sock.h" 
#include "errors.h"
#include <iostream>

extern "C" {
#include<unistd.h>
}

using namespace eMPTCP::xsk;
using namespace sock;

int main() {
    //make daemon 

    //xsk config 
    std::string ifname = "ens33";
    int queue = 0;
    std::list<XDPDesc> batch_data;
    auto xsk_conf = XSKSocketConfig();
    xsk_conf.tx_size = 4096;
    xsk_conf.rx_size = 0;   //no need to recv packets 
    
    //unix socket config 
    std::string un_path = "/tmp/emptcpd.socket";
    std::uint32_t buf_size = 1500;   //MTU

    //create XSK
    auto umem = std::make_shared<Umem>(UmemConfig());
    //xsk_conf.bind_flags = 0;
    //xsk_conf.libxdp_flags = 0;   
    XSKSocket xsk(ifname, queue, umem, xsk_conf);

    //create unix socket 
    auto un_sock = UnixSock();   //create and bind ;
    un_sock.bind(un_path);
    un_sock.listen(3);   
    utils::TermSignal::regist();
    while (true) {
        try {
            //SockAddrUn addr; 
            //utils::FileDescriptor fd;     //auto close fd 
            //std::tie(addr, fd.fd) = un_sock.accept<typename SockAddrUn::domain>();
            SockAddrUn accepted_addr;
            auto client_sock = Socket<SockAddrUn>(un_sock.accept(accepted_addr));
            std::cout << "accept : " << accepted_addr << '\n';

            while (true) {
                //alloc frame
                auto frame = xsk.alloc_frame();
                //recv data
                auto len = client_sock.recv(reinterpret_cast<char*>(umem->get_data(frame)), buf_size, 0);
                std::cout << "recv : " << len << "\n";
                //send copied packet by xsk 
                if (len == 0) {
                    break;
                }
                batch_data.emplace_front(frame, len, 0);
                xsk.send(batch_data.begin(), 1);
                batch_data.clear();

                std::cout << "send success \n";            
            }
        } catch (const errors::KeyboardInterrupt &e) {
            break;
        }
    }

    unlink(un_path.data());
    
}

#endif 
