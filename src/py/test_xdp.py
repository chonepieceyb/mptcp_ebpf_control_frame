#-*- coding:utf-8 -*-

from scapy.all import Ether, IP, raw, TCP, Raw, hexdump
from bcc import BPF, libbcc
import unittest
import ctypes as ct 
from prog_loader import TailCallLoader
from bpf_map_def import *
from bpf_loader import BPFBCCLoader
from action_tool import *

def raw_to_pkt(raw_pkt) : 
  pkt_byte = eval(str(raw_pkt))
  return Ether(pkt_byte)

class XDPTestCase(unittest.TestCase):
    SKB_OUT_SIZE = 1514 # mtu1500 + 14 eth size

    def xdp_test_run(self, given_packet, expected_packet, expected_return):
        size = len(given_packet)

        given_packet = ct.create_string_buffer(raw(given_packet), size)
        packet_output = ct.create_string_buffer(self.SKB_OUT_SIZE)
        
        packet_output_size = ct.c_uint32()
        test_retval = ct.c_uint32()
        duration = ct.c_uint32()
        repeat = 1 
        ret = libbcc.lib.bpf_prog_test_run(self.bpf_function.fd,
                                            repeat,
                                            ct.byref(given_packet),
                                            size,
                                            ct.byref(packet_output),
                                            ct.byref(packet_output_size),
                                            ct.byref(test_retval),
                                            ct.byref(duration))
        self.assertEqual(ret, 0)
        self.assertEqual(test_retval.value, expected_return)
        
        try:
          if expected_packet:
            self.assertEqual(
              packet_output[:packet_output_size.value], raw(expected_packet)
            )
        except Exception as e:
            print("+++++out packet+++++")
            output_pkt = raw_to_pkt(packet_output[:packet_output_size.value])
            output_pkt.show2()
            hexdump(output_pkt)
            print("++++recompute csum+++")
            tcphdr = output_pkt[TCP]
            del tcphdr.chksum
            tcphdr.show2()
            print("++++expected output+++")
            expected_packet.show2()
            hexdump(expected_packet)
            exit()
    
    def setup(self, bpf_function):
        self.bpf_function = bpf_function

def test_set_recv_win_ingress(xdp_tester):
    pkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 100)
    epkt = Ether(dst='ec:eb:b8:9c:59:99', src='ec:eb:b8:9c:69:6c')/IP(src='172.16.12.131', dst='172.16.12.128')/TCP(flags ='S', window = 1600)
    
    flow_actions = FlowIngressAction(local_addr = "172.16.12.128", peer_addr = "172.16.12.131")
    flow_actions.add("set_recv_win_in", ["--recv_win", "1600"])
    flow_actions.submit()
    xdp_tester.xdp_test_run(pkt, epkt, BPF.XDP_PASS)

if __name__ == '__main__':
    xdp_main = BPFBCCLoader(XDP_MAIN["src_path"], progs = XDP_MAIN["progs"], pin_maps = XDP_MAIN["pin_maps"], loaded = True, **XDP_MAIN["kw"])
    xdp_actions_fd = xdp_main.get_map_fd(XDP_ACTIONS)
    tailcall_loader = TailCallLoader(XDP_TAIL_CALL_LIST, BPFBCCLoader, loaded = True)
    tailcall_loader.load(xdp_actions_fd)

    
    tester = XDPTestCase()
    tester.setup(xdp_main.get_func("xdp_main"))

    test_set_recv_win_ingress(tester)
    xdp_main.unpin()
    tailcall_loader.unload()