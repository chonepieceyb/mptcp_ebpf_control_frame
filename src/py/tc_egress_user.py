#-*- coding:utf-8 -*-

from libbpf import *
import ctypes as ct 
from utils import *
from config import CONFIG
from data_struct_def import *
import os 

class TCEgressUser:
    def __init__(self):
        self.mptcp_output_fd = pin_mptcp_output()
        self.mptcp_connects_fd = pin_mptcp_connects()
        self.subflows_fd  = pin_subflows()
        self.perf_event_cb  = self._perf_event_cb

    #对于 perf event 可以考虑用线程池来做，就是有一个线程负责从 buffer 中拿东西，然后根据 cpu分配给其它的线程
    def run(self):
        with PerfBuffer(self.mptcp_output_fd, self.perf_event_cb) as pb:
            while True:
                try:
                    pb.poll()
                except KeyboardInterrupt:
                    break

    def _perf_event_cb(self, ctx, cpu, data, size):
        try:
            e = ct.cast(data, ct.POINTER(mp_capable_event_t)).contents
            peer_key = e.peer_key
            main_connect = e.connect

            #get token
            t = calc_sha1_token(val_2_bytes(peer_key, ct.sizeof(mptcp_key_type)))
            peer_token = bytes_2_val(t)
            peer_token_t = token_type(peer_token)

            #init val 
            mpc = mptcp_connect()
            setzero(mpc)   

            #set main flow 
            mpc.flow_nums = 1
            mpc.subflows[0] = main_connect

            print(self.mptcp_connects_fd)
            #update mptcp_connects 
            bpf_map_update_elem(self.mptcp_connects_fd, ct.pointer(peer_token_t), ct.pointer(mpc),BPF_MAP_UPDATE_ELEM_FLAG.BPF_NOEXIST)

            mf = subflow()
            setzero(mf)
            mf.address_id = MAIN_FLOW_ID
            mf.direction = direction.CLIENT
            mf.action = -1
            mf.token = peer_token
            mf.sended_pkts = 1;     #第三个握手包可以携带数据
            mf.sended_data = e.sended_data

            #update subflows 
            bpf_map_update_elem(self.subflows_fd, ct.pointer(main_connect), ct.pointer(mf), BPF_MAP_UPDATE_ELEM_FLAG.BPF_NOEXIST)

            #for testing 
            print("local_ip %s"%int2ip(int.from_bytes(val_2_bytes(main_connect.local_addr, 4), byteorder = "big", signed = False)))
            print("local_port %s"%int.from_bytes(val_2_bytes(main_connect.local_port, 2), byteorder = "big", signed = False))
            print("peer_ip %s"%int2ip(int.from_bytes(val_2_bytes(main_connect.peer_addr, 4), byteorder = "big", signed = False)))
            print("peer_port %s"%int.from_bytes(val_2_bytes(main_connect.peer_port, 2), byteorder = "big", signed = False))
            print("peer_key: %d"%int.from_bytes(val_2_bytes(e.peer_key, 8), byteorder = "big", signed = False))
            print("peer_token cal: %d"%int.from_bytes(t , byteorder = "big", signed = False))
            print("key val: %d"%peer_token)

        except Exception as e: 
            #这里使用异步的日志模块会比较好, 暂时还没来得及开发，先这样
            print(e)


def perf_event_cb(ctx, cpu, data, size):
        e = ct.cast(data, ct.POINTER(mp_capable_event_t)).contents
        
        #test 
        sender_key = e.sender_key
        connect = e.connect

        token = calc_sha1_token(val_2_bytes(sender_key, 8))

        #print
        print("src_ip %s"%int2ip(int.from_bytes(val_2_bytes(connect.saddr, 4), byteorder = "big", signed = False)))
        print("src_port %s"%int.from_bytes(val_2_bytes(connect.source, 2), byteorder = "big", signed = False))
        print("dest_ip %s"%int2ip(int.from_bytes(val_2_bytes(connect.daddr, 4), byteorder = "big", signed = False)))
        print("dest_port %s"%int.from_bytes(val_2_bytes(connect.dest, 2), byteorder = "big", signed = False))
        print("key: %d"%int.from_bytes(val_2_bytes(sender_key, 8), byteorder = "big", signed = False))
        print("token cal: %d"%int.from_bytes(t, byteorder = "big", signed = False))


if __name__ == '__main__' :
    tc_user = TCEgressUser()
    #tc_user.perf_event_cb = perf_event_cb
    tc_user.run()
    